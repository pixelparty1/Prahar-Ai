"""
crawler.py  –  Module 6
-----------------------
Crawls a live target application to discover endpoints.

Starting from the root URL it:
  • Follows internal links (HTML <a>, <form>)
  • Extracts fetch/XMLHttpRequest calls from inline JS
  • Parses REST-style routes
  • Returns a list of DiscoveredEndpoint-compatible dicts

Performance optimizations:
  • Fully async I/O via aiohttp (Opt 1 — async engine)
  • Concurrent page fetches + probes via asyncio.gather (Opt 2)
  • Connection pooling via TCPConnector (Opt 4)
  • Semaphore-based rate control (Opt 14)
  • URL normalization + dedup (Opt 7)

Does NOT modify any AttackBot code.
"""

from __future__ import annotations

import asyncio
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp

from async_engine import AsyncHTTPClient, run_sync

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
    Async crawler for live web application endpoint discovery.

    Uses aiohttp for concurrent page fetching and probing, with
    connection pooling and semaphore-based rate control.

    Parameters
    ----------
    base_url : str
        Root URL of the running application, e.g. ``http://127.0.0.1:5000``.
    max_pages : int
        Maximum number of pages to fetch (default 50).
    timeout : float
        HTTP request timeout in seconds.
    max_concurrent : int
        Maximum number of concurrent HTTP requests.
    """

    def __init__(
        self,
        base_url: str,
        max_pages: int = 50,
        timeout: float = 5.0,
        max_concurrent: int = 20,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._visited: Set[str] = set()
        self._endpoints: Set[CrawledEndpoint] = set()

    # ── Public API ────────────────────────────────────────────────────

    def crawl(self) -> List[CrawledEndpoint]:
        """
        Run the crawl and return all discovered endpoints (sync API).
        Internally uses async I/O for speed.

        Returns
        -------
        list[CrawledEndpoint]
        """
        result = run_sync(self._crawl_async())
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

    # ── Core async implementation ─────────────────────────────────────

    async def _crawl_async(self) -> List[CrawledEndpoint]:
        """Full async crawl: visit root, then probe common paths concurrently."""
        async with AsyncHTTPClient(
            max_concurrent=self.max_concurrent,
            timeout=self.timeout,
            conn_limit=self.max_concurrent + 10,
            user_agent="PrahaarCrawler/2.0",
        ) as client:
            # Phase 1: Visit root page and follow links
            await self._visit_async(client, self.base_url)

            # Phase 2: Probe common paths concurrently
            probes = [
                p for p in _COMMON_PROBES
                if (self.base_url + p) not in self._visited
                and len(self._visited) < self.max_pages
            ]
            if probes:
                tasks = [self._probe_async(client, path) for path in probes]
                await asyncio.gather(*tasks, return_exceptions=True)

        # Sort deterministically so every run produces the same endpoint order
        return sorted(
            self._endpoints,
            key=lambda ep: (ep.path, ep.method, tuple(sorted(ep.parameters))),
        )

    # ── Async visit (follows links recursively) ──────────────────────

    async def _visit_async(self, client: AsyncHTTPClient, url: str) -> None:
        """Fetch a page and extract endpoints from its content."""
        if url in self._visited or len(self._visited) >= self.max_pages:
            return
        self._visited.add(url)

        resp = await client.get(url, allow_redirects=True)
        if resp is None or resp.status >= 400:
            return

        try:
            body = await resp.text(errors="replace")
        except Exception:
            return

        parsed_base = urlparse(self.base_url)
        child_urls: List[str] = []

        # ── Extract <a href> links ────────────────────────────────────
        for match in _HREF_RE.finditer(body):
            href = match.group(1).strip()
            abs_url = urljoin(url, href)
            parsed = urlparse(abs_url)

            if parsed.netloc and parsed.netloc != parsed_base.netloc:
                continue

            path = parsed.path or "/"
            params = list(parse_qs(parsed.query).keys())
            self._add_endpoint(path, "GET", params, "href")

            if abs_url not in self._visited:
                child_urls.append(abs_url)

        # ── Extract <form> elements ───────────────────────────────────
        for form_match in _FORM_RE.finditer(body):
            action = form_match.group(1).strip()
            method = (form_match.group(2) or "GET").upper()
            abs_action = urljoin(url, action)
            parsed = urlparse(abs_action)

            if parsed.netloc and parsed.netloc != parsed_base.netloc:
                continue

            form_start = form_match.start()
            form_chunk = body[form_start: form_start + 3000]
            params = (
                _INPUT_RE.findall(form_chunk)
                + _SELECT_RE.findall(form_chunk)
                + _TEXTAREA_RE.findall(form_chunk)
            )
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

        # ── Recursively visit child pages (concurrently) ──────────────
        if child_urls:
            tasks = [
                self._visit_async(client, u) for u in child_urls
                if u not in self._visited and len(self._visited) < self.max_pages
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    # ── Async probe ───────────────────────────────────────────────────

    async def _probe_async(self, client: AsyncHTTPClient, path: str) -> None:
        """Try GET first; if the path is alive, also try POST."""
        url = self.base_url + path
        if url in self._visited:
            return
        self._visited.add(url)

        # GET probe first
        resp = await client.request("GET", url, allow_redirects=False)
        if resp is None or resp.status >= 404:
            return  # path doesn't exist — skip POST too

        # GET succeeded — extract params and record
        params: List[str] = []
        try:
            text = await resp.text(errors="replace")
            if text:
                params.extend(_INPUT_RE.findall(text))
                params.extend(_SELECT_RE.findall(text))
                params = list(dict.fromkeys(
                    p for p in params if p.lower() not in ("submit", "button")
                ))
        except Exception:
            pass
        self._add_endpoint(path, "GET", params, "probe")

        # POST probe on the same live path
        post_resp = await client.request("POST", url, allow_redirects=False)
        if post_resp is not None and post_resp.status < 500:
            post_params: List[str] = list(params)  # reuse GET params as base
            try:
                post_text = await post_resp.text(errors="replace")
                if post_text:
                    extra = _INPUT_RE.findall(post_text) + _SELECT_RE.findall(post_text)
                    for p in extra:
                        if p.lower() not in ("submit", "button") and p not in post_params:
                            post_params.append(p)
            except Exception:
                pass
            self._add_endpoint(path, "POST", post_params, "probe")

    # ── Internal: add endpoint ────────────────────────────────────────

    def _add_endpoint(
        self,
        path: str,
        method: str,
        parameters: List[str],
        source: str,
    ) -> None:
        """Add an endpoint to the set (auto-deduplicated via hash)."""
        # Normalise path (Opt 7 — endpoint deduplication)
        if not path.startswith("/"):
            path = "/" + path
        # Collapse double slashes → single
        while "//" in path:
            path = path.replace("//", "/")
        # Strip trailing slash (except root "/")
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

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
