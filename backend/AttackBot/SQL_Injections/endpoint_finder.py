"""
endpoint_finder.py
------------------
Scans uploaded project files (Python / Flask / Django / Express / PHP / etc.)
and discovers HTTP endpoints that accept user-controlled input.

Two discovery modes:
  1. **Static analysis** – parse source files for route definitions, form
     fields, and query parameters.
  2. **Live crawling** – if a running URL is provided, probe common paths.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import logging

logger = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────

@dataclass
class DiscoveredEndpoint:
    """Represents a single endpoint that may accept user input."""
    path: str
    method: str  # GET, POST, PUT, DELETE, etc.
    parameters: List[str] = field(default_factory=list)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    framework: Optional[str] = None

    def __hash__(self):
        return hash((self.path, self.method, tuple(self.parameters)))

    def __eq__(self, other):
        if not isinstance(other, DiscoveredEndpoint):
            return False
        return (self.path, self.method, tuple(self.parameters)) == (other.path, other.method, tuple(other.parameters))


# ── Regex patterns for various frameworks ─────────────────────────────────

# Flask / FastAPI / Quart
_FLASK_ROUTE_RE = re.compile(
    r"""@\w+\.route\(\s*["'](?P<path>[^"']+)["']"""
    r"""(?:\s*,\s*methods\s*=\s*\[(?P<methods>[^\]]+)\])?\s*\)""",
    re.IGNORECASE,
)

# request.form["param"], request.args.get("param"), request.args["param"],
# request.json["param"], request.json.get("param"), request.form.get("param")
_FLASK_PARAM_RE = re.compile(
    r"""request\.(?:form|args|json|values|data)\s*(?:\[["']|\.get\(\s*["'])(?P<param>[^"']+)["']\]?""",
    re.IGNORECASE,
)

# Django path() / url()
_DJANGO_ROUTE_RE = re.compile(
    r"""(?:path|url)\(\s*["'](?P<path>[^"']+)["']""",
    re.IGNORECASE,
)

# Express.js  app.get("/path", …)  /  router.post("/path", …)
_EXPRESS_ROUTE_RE = re.compile(
    r"""(?:app|router)\.(?P<method>get|post|put|delete|patch)\(\s*["'](?P<path>[^"']+)["']""",
    re.IGNORECASE,
)

# Express req.query.xxx / req.body.xxx / req.params.xxx
_EXPRESS_PARAM_RE = re.compile(
    r"""req\.(?:query|body|params)\.(?P<param>\w+)""",
    re.IGNORECASE,
)

# PHP: $_GET, $_POST, $_REQUEST
_PHP_PARAM_RE = re.compile(
    r"""\$_(?:GET|POST|REQUEST)\s*\[\s*["'](?P<param>[^"']+)["']\s*\]""",
    re.IGNORECASE,
)

# Generic SQL string concatenation (f-strings, format, %, +)
_SQL_CONCAT_RE = re.compile(
    r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*(?:\{|\%s|\+\s*\w+|'.*'\s*\+)""",
    re.IGNORECASE,
)

# Detect query parameters in URL-like strings  e.g. /search?q=
_URL_PARAM_RE = re.compile(
    r"""["'](?P<path>/[\w/\-]+)\?(?P<qparams>[^"']+)["']""",
)

# HTML form fields
_HTML_INPUT_RE = re.compile(
    r"""<input[^>]+name\s*=\s*["'](?P<param>[^"']+)["']""",
    re.IGNORECASE,
)
_HTML_FORM_ACTION_RE = re.compile(
    r"""<form[^>]+action\s*=\s*["'](?P<path>[^"']+)["'](?:[^>]+method\s*=\s*["'](?P<method>[^"']+)["'])?""",
    re.IGNORECASE,
)


# ── Static-analysis scanner ──────────────────────────────────────────────

class EndpointFinder:
    """
    Walk a project directory, parse source files, and extract endpoints +
    parameters that accept user input.
    """

    SUPPORTED_EXTENSIONS: Set[str] = {
        ".py", ".js", ".ts", ".php", ".html", ".htm", ".jsx", ".tsx",
    }

    def __init__(self, project_root: str):
        self.project_root = project_root
        self.endpoints: List[DiscoveredEndpoint] = []
        self._files_scanned: int = 0

    # ── Public API ────────────────────────────────────────────────────

    def scan(self) -> List[DiscoveredEndpoint]:
        """Walk the project tree and return all discovered endpoints."""
        self.endpoints.clear()
        self._files_scanned = 0

        for dirpath, _dirnames, filenames in os.walk(self.project_root):
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in self.SUPPORTED_EXTENSIONS:
                    full_path = os.path.join(dirpath, fname)
                    self._scan_file(full_path, ext)
                    self._files_scanned += 1

        # De-duplicate
        seen: Set[DiscoveredEndpoint] = set()
        unique: List[DiscoveredEndpoint] = []
        for ep in self.endpoints:
            if ep not in seen:
                seen.add(ep)
                unique.append(ep)
        self.endpoints = unique

        logger.info(
            "EndpointFinder scanned %d files, discovered %d endpoints.",
            self._files_scanned,
            len(self.endpoints),
        )
        return self.endpoints

    def scan_single_file(self, filepath: str) -> List[DiscoveredEndpoint]:
        """Scan a single file and return discovered endpoints."""
        ext = os.path.splitext(filepath)[1].lower()
        before = len(self.endpoints)
        self._scan_file(filepath, ext)
        return self.endpoints[before:]

    @property
    def files_scanned(self) -> int:
        return self._files_scanned

    # ── Internal scanners ─────────────────────────────────────────────

    def _scan_file(self, filepath: str, ext: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
                lines = content.splitlines()
        except OSError:
            logger.warning("Could not read file: %s", filepath)
            return

        if ext == ".py":
            self._scan_python(filepath, content, lines)
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            self._scan_javascript(filepath, content, lines)
        elif ext == ".php":
            self._scan_php(filepath, content, lines)
        elif ext in (".html", ".htm"):
            self._scan_html(filepath, content, lines)

    # ── Python (Flask / FastAPI / Django) ─────────────────────────────

    def _scan_python(self, filepath: str, content: str, lines: List[str]) -> None:
        # 1. Discover routes
        routes: List[Tuple[str, List[str], int]] = []  # (path, methods, line_no)

        for m in _FLASK_ROUTE_RE.finditer(content):
            path = m.group("path")
            raw_methods = m.group("methods")
            methods = (
                [s.strip().strip("'\"").upper() for s in raw_methods.split(",")]
                if raw_methods
                else ["GET"]
            )
            line_no = content[: m.start()].count("\n") + 1
            routes.append((path, methods, line_no))

        for m in _DJANGO_ROUTE_RE.finditer(content):
            path = "/" + m.group("path").strip("/")
            line_no = content[: m.start()].count("\n") + 1
            routes.append((path, ["GET", "POST"], line_no))

        # 2. Discover parameters used in request
        params: List[str] = [m.group("param") for m in _FLASK_PARAM_RE.finditer(content)]

        # 3. Detect URL query parameters
        for m in _URL_PARAM_RE.finditer(content):
            path = m.group("path")
            qparams = m.group("qparams")
            param_names = [p.split("=")[0] for p in qparams.split("&") if p]
            routes.append((path, ["GET"], content[: m.start()].count("\n") + 1))
            params.extend(param_names)

        # 4. Check for raw SQL concatenation (dangerous patterns)
        has_sql_concat = bool(_SQL_CONCAT_RE.search(content))

        # If we found routes, create endpoint objects
        if routes:
            unique_params = list(dict.fromkeys(params))  # preserve order, remove dupes
            for path, methods, line_no in routes:
                for method in methods:
                    ep = DiscoveredEndpoint(
                        path=path,
                        method=method,
                        parameters=unique_params if unique_params else self._extract_path_params(path),
                        source_file=filepath,
                        source_line=line_no,
                        framework="Flask/FastAPI" if _FLASK_ROUTE_RE.search(content) else "Django",
                    )
                    self.endpoints.append(ep)

        # Even without explicit routes, flag files with SQL concat + user input
        elif has_sql_concat and params:
            ep = DiscoveredEndpoint(
                path="<unknown>",
                method="POST",
                parameters=list(dict.fromkeys(params)),
                source_file=filepath,
                source_line=None,
                framework="Python",
            )
            self.endpoints.append(ep)

    # ── JavaScript / TypeScript (Express) ─────────────────────────────

    def _scan_javascript(self, filepath: str, content: str, lines: List[str]) -> None:
        routes: List[Tuple[str, str, int]] = []
        for m in _EXPRESS_ROUTE_RE.finditer(content):
            path = m.group("path")
            method = m.group("method").upper()
            line_no = content[: m.start()].count("\n") + 1
            routes.append((path, method, line_no))

        params = [m.group("param") for m in _EXPRESS_PARAM_RE.finditer(content)]

        for path, method, line_no in routes:
            ep = DiscoveredEndpoint(
                path=path,
                method=method,
                parameters=list(dict.fromkeys(params)) if params else self._extract_path_params(path),
                source_file=filepath,
                source_line=line_no,
                framework="Express",
            )
            self.endpoints.append(ep)

    # ── PHP ───────────────────────────────────────────────────────────

    def _scan_php(self, filepath: str, content: str, lines: List[str]) -> None:
        params = [m.group("param") for m in _PHP_PARAM_RE.finditer(content)]
        if params:
            # PHP files are often the endpoint themselves
            rel = os.path.relpath(filepath, self.project_root).replace("\\", "/")
            ep = DiscoveredEndpoint(
                path=f"/{rel}",
                method="GET/POST",
                parameters=list(dict.fromkeys(params)),
                source_file=filepath,
                framework="PHP",
            )
            self.endpoints.append(ep)

    # ── HTML ──────────────────────────────────────────────────────────

    def _scan_html(self, filepath: str, content: str, lines: List[str]) -> None:
        params = [m.group("param") for m in _HTML_INPUT_RE.finditer(content)]
        for m in _HTML_FORM_ACTION_RE.finditer(content):
            path = m.group("path")
            method = (m.group("method") or "GET").upper()
            line_no = content[: m.start()].count("\n") + 1
            ep = DiscoveredEndpoint(
                path=path,
                method=method,
                parameters=list(dict.fromkeys(params)),
                source_file=filepath,
                source_line=line_no,
                framework="HTML",
            )
            self.endpoints.append(ep)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_path_params(path: str) -> List[str]:
        """Extract Flask-style ``<param>`` or Express-style ``:param`` from a path."""
        flask = re.findall(r"<(?:\w+:)?(\w+)>", path)
        express = re.findall(r":(\w+)", path)
        return flask + express


# ── Live URL probing (lightweight) ────────────────────────────────────────

COMMON_PATHS = [
    "/login", "/signin", "/signup", "/register",
    "/search", "/api/search",
    "/api/user", "/api/users",
    "/api/product", "/api/products",
    "/admin", "/dashboard",
    "/profile", "/account",
    "/api/login", "/api/register",
    "/api/query", "/api/data",
    "/comment", "/feedback",
    "/api/v1/login", "/api/v1/users",
]


def probe_live_endpoints(
    base_url: str,
    paths: Optional[List[str]] = None,
    timeout: float = 5.0,
) -> List[DiscoveredEndpoint]:
    """
    Probe a running web application for common endpoint paths and return
    those that respond with a non-404 status.
    """
    import requests  # deferred import — only needed for live probing

    paths = paths or COMMON_PATHS
    found: List[DiscoveredEndpoint] = []
    base_url = base_url.rstrip("/")

    for path in paths:
        url = f"{base_url}{path}"
        for method in ("GET", "POST"):
            try:
                resp = requests.request(method, url, timeout=timeout, allow_redirects=False)
                if resp.status_code not in (404, 405):
                    ep = DiscoveredEndpoint(
                        path=path,
                        method=method,
                        parameters=[],
                        framework="Live",
                    )
                    found.append(ep)
            except requests.RequestException:
                continue

    logger.info("Live probe found %d endpoints at %s", len(found), base_url)
    return found
