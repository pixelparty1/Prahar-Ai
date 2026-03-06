"""
xss_attack_bot.py
-----------------
Cross-Site Scripting (XSS) vulnerability detection engine.

Supports detection of:
  1.  Reflected XSS
  2.  Stored XSS
  3.  DOM-Based XSS  (static JS analysis)
  4.  Blind XSS
  5.  Event Handler XSS
  6.  Attribute Injection XSS
  7.  JavaScript URI XSS
  8.  Template Injection XSS
  9.  Mutation XSS
  10. Polyglot XSS

This module is COMPLETELY INDEPENDENT of the SQL injection pipeline.
It does not import from or modify any SQL injection module.

Usage
-----
    from AttackBot.XSS_Attacks.xss_attack_bot import XSSAttackBot, XSSScanConfig

    bot = XSSAttackBot(target_url="http://127.0.0.1:5000", project_dir="/path/to/src")
    findings = bot.run_scan(endpoints)
    for f in findings:
        print(f.xss_type, f.severity, f.endpoint, f.parameter)
"""

from __future__ import annotations

import html
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests

from .xss_payloads import (
    ALL_XSS_CATEGORIES,
    ATTRIBUTE_INJECTION_PAYLOADS,
    BLIND_XSS_PAYLOADS,
    DOM_PROBE_PAYLOADS,
    EVENT_HANDLER_PAYLOADS,
    JS_URI_PAYLOADS,
    MUTATION_PAYLOADS,
    POLYGLOT_PAYLOADS,
    REFLECTED_PAYLOADS,
    STORED_PAYLOADS,
    TEMPLATE_INJECTION_PAYLOADS,
    XSSPayloadCategory,
)

logger = logging.getLogger(__name__)


# ── XSS type enumeration ──────────────────────────────────────────────────

class XSSType(str, Enum):
    REFLECTED           = "Reflected XSS"
    STORED              = "Stored XSS"
    DOM_BASED           = "DOM-Based XSS"
    BLIND               = "Blind XSS"
    EVENT_HANDLER       = "Event Handler XSS"
    ATTRIBUTE_INJECTION = "Attribute Injection XSS"
    JS_URI              = "JavaScript URI XSS"
    TEMPLATE_INJECTION  = "Template Injection XSS"
    MUTATION            = "Mutation XSS"
    POLYGLOT            = "Polyglot XSS"


# ── Severity map ──────────────────────────────────────────────────────────

XSS_SEVERITY: Dict[XSSType, str] = {
    XSSType.REFLECTED:           "HIGH",
    XSSType.STORED:              "CRITICAL",
    XSSType.DOM_BASED:           "HIGH",
    XSSType.BLIND:               "HIGH",
    XSSType.EVENT_HANDLER:       "HIGH",
    XSSType.ATTRIBUTE_INJECTION: "HIGH",
    XSSType.JS_URI:              "HIGH",
    XSSType.TEMPLATE_INJECTION:  "CRITICAL",
    XSSType.MUTATION:            "HIGH",
    XSSType.POLYGLOT:            "HIGH",
}


# ── Scan configuration ────────────────────────────────────────────────────

@dataclass
class XSSScanConfig:
    """Tuneable parameters for an XSS scan run."""
    timeout: float = 8.0
    delay_between_requests: float = 0.05
    max_payloads_per_category: int = 0          # 0 = unlimited
    skip_blind: bool = True                     # Blind XSS payloads need OOB infra
    skip_stored_verification: bool = False      # Re-fetch page to confirm stored XSS
    user_agent: str = "XSSAttackBot/1.0 (Prahaar_AI Security Scanner)"
    verify_ssl: bool = False
    verbose: bool = False


# ── XSS finding ──────────────────────────────────────────────────────────

@dataclass
class XSSFinding:
    """A single confirmed or probable XSS vulnerability."""
    xss_type: XSSType
    severity: str
    endpoint: str
    parameter: str
    method: str
    payload: str
    evidence: str
    confidence: str                         # "CONFIRMED" | "PROBABLE" | "POTENTIAL"
    source_file: str = ""                   # for DOM-based / static findings
    source_line: int = 0
    raw_response_snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "xss_type": self.xss_type.value,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "response_snippet": self.raw_response_snippet[:300],
        }


# ── DOM-based static patterns ─────────────────────────────────────────────

_DOM_SINK_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"""\.innerHTML\s*=\s*(?!["'`][\s]*["'`])"""),             "innerHTML assignment"),
    (re.compile(r"""\.outerHTML\s*=\s*"""),                                 "outerHTML assignment"),
    (re.compile(r"""document\.write\s*\("""),                               "document.write()"),
    (re.compile(r"""document\.writeln\s*\("""),                             "document.writeln()"),
    (re.compile(r"""\beval\s*\("""),                                        "eval()"),
    (re.compile(r"""setTimeout\s*\(\s*(?!function|[`"'])"""),               "setTimeout() with non-literal"),
    (re.compile(r"""setInterval\s*\(\s*(?!function|[`"'])"""),              "setInterval() with non-literal"),
    (re.compile(r"""location\.href\s*=\s*(?!["'`])"""),                    "location.href assignment"),
    (re.compile(r"""location\.replace\s*\("""),                             "location.replace()"),
    (re.compile(r"""location\.assign\s*\("""),                              "location.assign()"),
    (re.compile(r"""location\.hash"""),                                     "location.hash usage"),
    (re.compile(r"""location\.search"""),                                   "location.search usage"),
    (re.compile(r"""document\.URL"""),                                      "document.URL usage"),
    (re.compile(r"""document\.referrer"""),                                 "document.referrer usage"),
    (re.compile(r"""window\.name"""),                                       "window.name usage"),
    (re.compile(r"""insertAdjacentHTML\s*\("""),                            "insertAdjacentHTML()"),
    (re.compile(r"""jQuery\.parseHTML\s*\("""),                             "jQuery.parseHTML()"),
    (re.compile(r"""\$\s*\(\s*(?:location|document\.URL|window\.name)"""), "jQuery() with URL input"),
]

_JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs"}
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "vendor", "out", "target",
}
_MAX_JS_FILE_SIZE = 512 * 1024  # 512 KB


# ── Stored XSS field names ────────────────────────────────────────────────

_STORED_FIELD_HINTS = {
    "comment", "review", "message", "bio", "description",
    "content", "text", "body", "note", "feedback", "title",
    "name", "username", "profile", "about",
}

# ── Template injection verification ──────────────────────────────────────

_TEMPLATE_EVAL_MARKERS = ["49", "{{7*7}}", "${7*7}", "49.0"]

# ── XSSAttackBot ─────────────────────────────────────────────────────────

class XSSAttackBot:
    """
    Cross-Site Scripting vulnerability detection engine.

    Completely independent from the SQL injection pipeline.

    Stages
    ------
    1. Payload injection scan  → detect reflected / event-handler / attribute /
       JS-URI / polyglot / mutation / template payloads in live responses
    2. Stored XSS verification → re-fetch pages after submission
    3. DOM static analysis     → scan JS files for dangerous sinks
    """

    def __init__(
        self,
        target_url: str = "",
        project_dir: Optional[str] = None,
        config: Optional[XSSScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.project_dir = project_dir
        self.config = config or XSSScanConfig()

        self._findings: List[XSSFinding] = []
        self._session: Optional[requests.Session] = None

    # ── Public API ────────────────────────────────────────────────────

    def run_scan(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> List[XSSFinding]:
        """
        Execute the full XSS scan.

        Parameters
        ----------
        endpoints : list[dict] | None
            Each dict: ``{"path": str, "method": str, "parameters": [str]}``
            If None, the bot will try to probe common paths.

        Returns
        -------
        list[XSSFinding]
        """
        self._findings = []

        # ── 1. Live injection scan ────────────────────────────────────
        if self.target_url:
            self._session = requests.Session()
            self._session.headers["User-Agent"] = self.config.user_agent
            self._session.verify = self.config.verify_ssl

            targets = endpoints or []
            if not targets:
                # Probe common paths
                targets = self._probe_common_endpoints()

            for ep in targets:
                path       = ep.get("path", "/")
                method     = ep.get("method", "GET").upper()
                parameters = ep.get("parameters") or ["q", "search", "input"]
                for param in parameters:
                    self._scan_parameter(path, method, param)

            self._session.close()
            self._session = None

        # ── 2. DOM static analysis ────────────────────────────────────
        if self.project_dir and os.path.isdir(self.project_dir):
            self._dom_static_scan(self.project_dir)

        if self.config.verbose:
            logger.info(
                "[XSSAttackBot] Scan complete. %d finding(s) on %s",
                len(self._findings),
                self.target_url or "static-only",
            )

        return self._findings

    # ── 2. Parameter scanner ──────────────────────────────────────────

    def _scan_parameter(self, path: str, method: str, parameter: str) -> None:
        """Inject every XSS payload into a single endpoint parameter."""
        url = f"{self.target_url}{path}"

        # Fetch a clean baseline first
        baseline_body = self._fetch(url, method, parameter, "xss_baseline_value")
        if baseline_body is None:
            return

        active_categories = self._get_active_categories()

        for category in active_categories:
            payloads = category.payloads
            if self.config.max_payloads_per_category > 0:
                payloads = payloads[: self.config.max_payloads_per_category]

            for payload in payloads:
                response_body = self._fetch(url, method, parameter, payload)
                if response_body is None:
                    continue

                finding = self._analyze_response(
                    payload=payload,
                    category=category,
                    response_body=response_body,
                    baseline_body=baseline_body,
                    endpoint=path,
                    parameter=parameter,
                    method=method,
                )

                if finding:
                    self._findings.append(finding)

                    # Stored XSS: re-fetch the page to confirm persistence
                    if (
                        finding.xss_type == XSSType.STORED
                        and not self.config.skip_stored_verification
                    ):
                        self._verify_stored(url, method, parameter, payload, path)

                time.sleep(self.config.delay_between_requests)

    # ── 3. Response analysis ──────────────────────────────────────────

    def _analyze_response(
        self,
        payload: str,
        category: "XSSPayloadCategory",
        response_body: str,
        baseline_body: str,
        endpoint: str,
        parameter: str,
        method: str,
    ) -> Optional[XSSFinding]:
        """
        Determine whether a payload was reflected unescaped in the response.
        Returns an XSSFinding or None.
        """
        category_name = category.name
        payload_lower = payload.lower()

        # ── Check 1: Raw payload reflection (unescaped) ───────────────
        if payload in response_body:
            xss_type  = self._classify_type(category_name, payload)
            evidence  = f"Payload reflected verbatim in response without HTML encoding."
            snippet   = self._extract_snippet(response_body, payload)
            return XSSFinding(
                xss_type=xss_type,
                severity=XSS_SEVERITY[xss_type],
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                payload=payload,
                evidence=evidence,
                confidence="CONFIRMED",
                raw_response_snippet=snippet,
            )

        # ── Check 2: HTML-decoded payload reflected ───────────────────
        decoded_payload = html.unescape(payload)
        if decoded_payload != payload and decoded_payload in response_body:
            xss_type = self._classify_type(category_name, payload)
            return XSSFinding(
                xss_type=xss_type,
                severity=XSS_SEVERITY[xss_type],
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                payload=payload,
                evidence="HTML-decoded payload appears in response — server decodes before outputting.",
                confidence="CONFIRMED",
                raw_response_snippet=self._extract_snippet(response_body, decoded_payload),
            )

        # ── Check 3: Template injection marker ───────────────────────
        if category_name == TEMPLATE_INJECTION_PAYLOADS.name:
            for marker in _TEMPLATE_EVAL_MARKERS:
                if marker in response_body and marker not in baseline_body:
                    return XSSFinding(
                        xss_type=XSSType.TEMPLATE_INJECTION,
                        severity=XSS_SEVERITY[XSSType.TEMPLATE_INJECTION],
                        endpoint=endpoint,
                        parameter=parameter,
                        method=method,
                        payload=payload,
                        evidence=f"Template expression evaluated — marker '{marker}' present in response.",
                        confidence="CONFIRMED",
                        raw_response_snippet=self._extract_snippet(response_body, marker),
                    )

        # ── Check 4: Partial reflection (tag/event stripped but present) ──
        partial_indicators = self._partial_reflection(payload, response_body)
        if partial_indicators:
            xss_type = self._classify_type(category_name, payload)
            return XSSFinding(
                xss_type=xss_type,
                severity=XSS_SEVERITY[xss_type],
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                payload=payload,
                evidence=f"Partial payload reflection detected: {partial_indicators}",
                confidence="PROBABLE",
                raw_response_snippet=partial_indicators,
            )

        return None

    # ── 4. Stored XSS verification ────────────────────────────────────

    def _verify_stored(
        self,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        endpoint: str,
    ) -> None:
        """Re-fetch the page after storing a payload and look for persistence."""
        if self._session is None:
            return
        try:
            time.sleep(0.3)
            resp = self._session.get(url, timeout=self.config.timeout, verify=False)
            if payload in resp.text:
                self._findings.append(XSSFinding(
                    xss_type=XSSType.STORED,
                    severity=XSS_SEVERITY[XSSType.STORED],
                    endpoint=endpoint,
                    parameter=parameter,
                    method=method,
                    payload=payload,
                    evidence="Payload persists on page reload — confirmed Stored XSS.",
                    confidence="CONFIRMED",
                    raw_response_snippet=self._extract_snippet(resp.text, payload),
                ))
        except requests.RequestException:
            pass

    # ── 5. DOM static analysis ────────────────────────────────────────

    def _dom_static_scan(self, directory: str) -> None:
        """Walk JS/TS files looking for dangerous DOM sink patterns."""
        for dirpath, dirnames, filenames in os.walk(directory):
            # Prune skip dirs in-place
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _JS_EXTENSIONS:
                    continue

                full_path = os.path.join(dirpath, fname)
                try:
                    if os.path.getsize(full_path) > _MAX_JS_FILE_SIZE:
                        continue
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        lines = content.splitlines()
                except OSError:
                    continue

                for pattern, description in _DOM_SINK_PATTERNS:
                    for m in pattern.finditer(content):
                        line_no = content[: m.start()].count("\n") + 1
                        code = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                        self._findings.append(XSSFinding(
                            xss_type=XSSType.DOM_BASED,
                            severity=XSS_SEVERITY[XSSType.DOM_BASED],
                            endpoint="<static-analysis>",
                            parameter="<dom-sink>",
                            method="N/A",
                            payload=code[:120],
                            evidence=f"Dangerous DOM sink detected: {description}",
                            confidence="POTENTIAL",
                            source_file=full_path,
                            source_line=line_no,
                        ))

    # ── 6. HTTP helper ────────────────────────────────────────────────

    def _fetch(
        self,
        url: str,
        method: str,
        parameter: str,
        value: str,
    ) -> Optional[str]:
        """Send a single HTTP request. Returns body or None on failure."""
        assert self._session is not None
        try:
            if method in ("GET", "HEAD", "OPTIONS"):
                resp = self._session.request(
                    method, url,
                    params={parameter: value},
                    timeout=self.config.timeout,
                    allow_redirects=True,
                )
            else:
                resp = self._session.request(
                    method, url,
                    data={parameter: value},
                    timeout=self.config.timeout,
                    allow_redirects=True,
                )
            return resp.text
        except requests.RequestException as exc:
            logger.debug("[XSSAttackBot] Request failed (%s %s ?%s=%s): %s",
                         method, url, parameter, value[:30], exc)
            return None

    # ── 7. Probe common paths ─────────────────────────────────────────

    def _probe_common_endpoints(self) -> List[Dict[str, Any]]:
        """Return a minimal list of common endpoints if none were crawled."""
        return [
            {"path": "/search",   "method": "GET",  "parameters": ["q", "query", "search", "s"]},
            {"path": "/",         "method": "GET",  "parameters": ["q", "search"]},
            {"path": "/login",    "method": "POST", "parameters": ["username", "password"]},
            {"path": "/comment",  "method": "POST", "parameters": ["comment", "message", "text"]},
            {"path": "/profile",  "method": "POST", "parameters": ["bio", "name", "username"]},
            {"path": "/api/search","method": "GET", "parameters": ["q", "term"]},
            {"path": "/feedback", "method": "POST", "parameters": ["message", "feedback"]},
        ]

    # ── 8. Category selection ─────────────────────────────────────────

    def _get_active_categories(self) -> List["XSSPayloadCategory"]:
        cats = list(ALL_XSS_CATEGORIES)
        if self.config.skip_blind:
            cats = [c for c in cats if c.name != BLIND_XSS_PAYLOADS.name]
        # Skip DOM probe payloads in live scan (handled by static analysis)
        cats = [c for c in cats if c.name != DOM_PROBE_PAYLOADS.name]
        return cats

    # ── 9. Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _classify_type(category_name: str, payload: str) -> XSSType:
        """Map a category name to an XSSType enum."""
        mapping = {
            "Reflected XSS":           XSSType.REFLECTED,
            "Stored XSS":              XSSType.STORED,
            "DOM-Based XSS":           XSSType.DOM_BASED,
            "Blind XSS":               XSSType.BLIND,
            "Event Handler XSS":       XSSType.EVENT_HANDLER,
            "Attribute Injection XSS": XSSType.ATTRIBUTE_INJECTION,
            "JavaScript URI XSS":      XSSType.JS_URI,
            "Template Injection XSS":  XSSType.TEMPLATE_INJECTION,
            "Mutation XSS":            XSSType.MUTATION,
            "Polyglot XSS":            XSSType.POLYGLOT,
        }
        return mapping.get(category_name, XSSType.REFLECTED)

    @staticmethod
    def _extract_snippet(body: str, needle: str, context: int = 80) -> str:
        """Return a short context window around the needle in body."""
        idx = body.find(needle)
        if idx == -1:
            return ""
        start = max(0, idx - context)
        end   = min(len(body), idx + len(needle) + context)
        return body[start:end].strip()

    @staticmethod
    def _partial_reflection(payload: str, response_body: str) -> str:
        """
        Check whether key structural parts of the payload appear in the
        response even if the full payload was sanitised.
        Returns a short snippet if partial reflection found, else "".
        """
        # Extract the most dangerous atom — the tag or event name
        # e.g. from "<img src=x onerror=alert(1)>" → "onerror"
        matches = re.findall(
            r"(?:on\w+|innerHTML|eval|script|javascript|alert|onerror|onload|onclick)",
            payload,
            re.IGNORECASE,
        )
        for atom in matches:
            if atom.lower() in response_body.lower():
                # Find it in body for a snippet
                idx = response_body.lower().find(atom.lower())
                snippet = response_body[max(0, idx - 30): idx + len(atom) + 30].strip()
                return f"'{atom}' reflected at: ...{snippet}..."
        return ""

    # ── Accessors ─────────────────────────────────────────────────────

    @property
    def findings(self) -> List[XSSFinding]:
        return self._findings

    def get_findings_as_dicts(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self._findings]

    def findings_summary(self) -> Dict[str, Any]:
        """Return a compact summary of findings."""
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for f in self._findings:
            by_type[f.xss_type.value]   = by_type.get(f.xss_type.value, 0) + 1
            by_severity[f.severity]      = by_severity.get(f.severity, 0) + 1
        return {
            "total_xss_findings": len(self._findings),
            "by_type": by_type,
            "by_severity": by_severity,
        }
