"""
crawler.py  –  Module 6
-----------------------
Crawls a live target application to discover endpoints.

Starting from the root URL it:
  • Follows internal links (HTML <a>, <form>)
  • Extracts fetch/XMLHttpRequest calls from inline JS
  • Parses REST-style routes
  • Returns a list of DiscoveredEndpoint-compatible dicts

Does NOT modify any AttackBot code.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import requests

logger = logging.getLogger(__name__)


# ── Data-classes ──────────────────────────────────────────────────────────

@dataclass
class CrawledEndpoint:
    """Lightweight endpoint descriptor produced by the crawler."""
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source: str = ""  # where we found it (href, form, js, probe)

    def __hash__(self):
        return hash((self.path, self.method, tuple(sorted(self.parameters))))

    def __eq__(self, other):
        if not isinstance(other, CrawledEndpoint):
            return False
        return (self.path, self.method, tuple(sorted(self.parameters))) == (
            other.path, other.method, tuple(sorted(other.parameters))
        )


# ── Regex helpers ─────────────────────────────────────────────────────────

_HREF_RE = re.compile(r'<a\s[^>]*href\s*=\s*["\']([^"\'#]+)', re.IGNORECASE)
_FORM_RE = re.compile(
    r'<form\s[^>]*action\s*=\s*["\']([^"\']+)["\'][^>]*'
    r'(?:method\s*=\s*["\'](\w+)["\'])?',
    re.IGNORECASE | re.DOTALL,
)
_INPUT_RE = re.compile(
    r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)
_SELECT_RE = re.compile(
    r'<select[^>]+name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)
_TEXTAREA_RE = re.compile(
    r'<textarea[^>]+name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)
_JS_FETCH_RE = re.compile(
    r'''fetch\s*\(\s*[`"']([^`"']+)[`"'](?:\s*,\s*\{[^}]*method\s*:\s*[`"'](\w+)[`"'])?''',
    re.IGNORECASE,
)
_JS_XHR_RE = re.compile(
    r'''\.open\s*\(\s*[`"'](\w+)[`"']\s*,\s*[`"']([^`"']+)[`"']''',
    re.IGNORECASE,
)
_QUERY_PARAM_URL_RE = re.compile(r'["\'](/[\w/\-]+)\?([^"\']+)["\']')

# Common probe paths that might not be linked
_COMMON_PROBES = [
    "/", "/login", "/search", "/api", "/api/user", "/api/users",
    "/register", "/admin", "/product", "/products", "/comment",
    "/comments", "/profile", "/dashboard", "/logout",
]


# ── Crawler ───────────────────────────────────────────────────────────────

class Crawler:
    """
    Crawl a live web application to discover endpoints.

    Parameters
    ----------
    base_url : str
        Root URL of the running application, e.g. ``http://127.0.0.1:5000``.
    max_pages : int
        Maximum number of pages to fetch (default 50).
    timeout : float
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        max_pages: int = 50,
        timeout: float = 5.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self._visited: Set[str] = set()
        self._endpoints: Set[CrawledEndpoint] = set()
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "PrahaarCrawler/1.0"

    # ── Public API ────────────────────────────────────────────────────

    def crawl(self) -> List[CrawledEndpoint]:
        """
        Run the crawl and return all discovered endpoints.

        Returns
        -------
        list[CrawledEndpoint]
        """
        # Start with the root page
        self._visit(self.base_url)

        # Probe common paths that may not be linked
        for probe_path in _COMMON_PROBES:
            url = self.base_url + probe_path
            if url not in self._visited and len(self._visited) < self.max_pages:
                self._probe(probe_path)

        self._session.close()
        result = list(self._endpoints)
        logger.info("[Crawler] Discovered %d endpoints at %s", len(result), self.base_url)
        return result

    def get_endpoints_as_dicts(self) -> List[Dict]:
        """Return crawled endpoints as plain dicts (for serialization)."""
        return [
            {
                "path": ep.path,
                "method": ep.method,
                "parameters": ep.parameters,
                "source": ep.source,
            }
            for ep in self._endpoints
        ]

    # ── Internal: visit a page ────────────────────────────────────────

    def _visit(self, url: str) -> None:
        """Fetch a page and extract endpoints from its content."""
        if url in self._visited or len(self._visited) >= self.max_pages:
            return
        self._visited.add(url)

        try:
            resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as exc:
            logger.debug("[Crawler] Failed to fetch %s: %s", url, exc)
            return

        if resp.status_code >= 400:
            return

        body = resp.text
        parsed_base = urlparse(self.base_url)

        # ── Extract <a href> links ────────────────────────────────────
        for match in _HREF_RE.finditer(body):
            href = match.group(1).strip()
            abs_url = urljoin(url, href)
            parsed = urlparse(abs_url)

            # Only follow same-host links
            if parsed.netloc and parsed.netloc != parsed_base.netloc:
                continue

            path = parsed.path or "/"
            params = list(parse_qs(parsed.query).keys())
            self._add_endpoint(path, "GET", params, "href")

            # Recurse into internal pages
            if abs_url not in self._visited:
                self._visit(abs_url)

        # ── Extract <form> elements ───────────────────────────────────
        for form_match in _FORM_RE.finditer(body):
            action = form_match.group(1).strip()
            method = (form_match.group(2) or "GET").upper()
            abs_action = urljoin(url, action)
            parsed = urlparse(abs_action)

            if parsed.netloc and parsed.netloc != parsed_base.netloc:
                continue

            # Find input fields within a reasonable range after the <form> tag
            form_start = form_match.start()
            form_chunk = body[form_start: form_start + 3000]
            params = (
                _INPUT_RE.findall(form_chunk)
                + _SELECT_RE.findall(form_chunk)
                + _TEXTAREA_RE.findall(form_chunk)
            )
            # Deduplicate, strip submit buttons
            params = list(dict.fromkeys(
                p for p in params if p.lower() not in ("submit", "button", "csrf_token")
            ))

            path = parsed.path or "/"
            self._add_endpoint(path, method, params, "form")

        # ── Extract JS fetch() / XMLHttpRequest ───────────────────────
        for m in _JS_FETCH_RE.finditer(body):
            fetch_url = m.group(1).strip()
            fetch_method = (m.group(2) or "GET").upper()
            if fetch_url.startswith("/") or fetch_url.startswith(self.base_url):
                parsed = urlparse(urljoin(self.base_url, fetch_url))
                params = list(parse_qs(parsed.query).keys())
                self._add_endpoint(parsed.path or "/", fetch_method, params, "js_fetch")

        for m in _JS_XHR_RE.finditer(body):
            xhr_method = m.group(1).upper()
            xhr_url = m.group(2).strip()
            if xhr_url.startswith("/") or xhr_url.startswith(self.base_url):
                parsed = urlparse(urljoin(self.base_url, xhr_url))
                params = list(parse_qs(parsed.query).keys())
                self._add_endpoint(parsed.path or "/", xhr_method, params, "js_xhr")

        # ── Extract query-param URLs from strings ─────────────────────
        for m in _QUERY_PARAM_URL_RE.finditer(body):
            path = m.group(1)
            qs = m.group(2)
            params = list(parse_qs(qs).keys())
            self._add_endpoint(path, "GET", params, "url_string")

    # ── Internal: probe a path ────────────────────────────────────────

    def _probe(self, path: str) -> None:
        """Try GET and POST to see if a path is alive."""
        url = self.base_url + path
        if url in self._visited:
            return
        self._visited.add(url)

        for method in ("GET", "POST"):
            try:
                resp = self._session.request(
                    method, url, timeout=self.timeout, allow_redirects=False,
                )
                if resp.status_code < 500:
                    # Alive — extract params from the response body
                    params: List[str] = []
                    if resp.text:
                        params.extend(_INPUT_RE.findall(resp.text))
                        params.extend(_SELECT_RE.findall(resp.text))
                        params = list(dict.fromkeys(
                            p for p in params if p.lower() not in ("submit", "button")
                        ))
                    self._add_endpoint(path, method, params, "probe")
            except Exception:
                pass

    # ── Internal: add endpoint ────────────────────────────────────────

    def _add_endpoint(
        self,
        path: str,
        method: str,
        parameters: List[str],
        source: str,
    ) -> None:
        """Add an endpoint to the set (auto-deduplicated via hash)."""
        # Normalise path
        if not path.startswith("/"):
            path = "/" + path

        ep = CrawledEndpoint(
            path=path,
            method=method.upper(),
            parameters=parameters,
            source=source,
        )
        self._endpoints.add(ep)


# ── Convenience ───────────────────────────────────────────────────────────

def crawl_target(
    base_url: str,
    max_pages: int = 50,
    timeout: float = 5.0,
) -> List[CrawledEndpoint]:
    """One-shot crawl. Returns list of CrawledEndpoint."""
    return Crawler(base_url, max_pages=max_pages, timeout=timeout).crawl()
