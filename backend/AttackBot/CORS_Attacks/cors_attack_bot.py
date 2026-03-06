"""
cors_attack_bot.py
------------------
Cross-Origin Resource Sharing (CORS) misconfiguration detection engine.

Supports detection of:
  1.  Wildcard Origin (Access-Control-Allow-Origin: *)
  2.  Origin Reflection (server echoes arbitrary Origin)
  3.  Credentials with Wildcard Origin (CRITICAL)
  4.  Null Origin Acceptance
  5.  Preflight Misconfiguration (overly permissive OPTIONS)
  6.  Subdomain Trust Misconfiguration (wildcard subdomain ACAO)
  7.  Insecure Protocol Trust (HTTP origin accepted)
  8.  Sensitive Data Exposure via CORS (JSON + sensitive keywords + ACAO)
  9.  Insecure Allowed Headers (Authorization / * in ACAH)
  10. Improper CORS with JSON APIs (JSON Content-Type + ACAO: *)

This module is COMPLETELY INDEPENDENT of the SQL injection and XSS pipelines.
It does not import from or modify any SQL injection or XSS module.

Usage
-----
    from AttackBot.CORS_Attacks.cors_attack_bot import CORSAttackBot, CORSScanConfig

    bot = CORSAttackBot(target_url="http://127.0.0.1:5000")
    findings = bot.run_scan(endpoints)
    for f in findings:
        print(f.issue_type, f.severity, f.endpoint)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

from .cors_payloads import get_all_origins

logger = logging.getLogger(__name__)


# ── CORS issue type enumeration ───────────────────────────────────────────

class CORSIssueType(str, Enum):
    WILDCARD_ORIGIN       = "Wildcard Origin Allowed"
    ORIGIN_REFLECTION     = "Origin Reflection"
    CREDENTIALS_WILDCARD  = "Credentials with Wildcard Origin"
    NULL_ORIGIN           = "Null Origin Acceptance"
    PREFLIGHT_MISCONFIG   = "Preflight Misconfiguration"
    SUBDOMAIN_TRUST       = "Subdomain Trust Misconfiguration"
    INSECURE_PROTOCOL     = "Insecure Protocol Trust"
    SENSITIVE_DATA_CORS   = "Sensitive Data Exposure via CORS"
    INSECURE_HEADERS      = "Insecure Allowed Headers"
    JSON_API_CORS         = "Improper CORS with JSON APIs"


# ── Severity map ──────────────────────────────────────────────────────────

CORS_SEVERITY: Dict[CORSIssueType, str] = {
    CORSIssueType.WILDCARD_ORIGIN:      "HIGH",
    CORSIssueType.ORIGIN_REFLECTION:    "HIGH",
    CORSIssueType.CREDENTIALS_WILDCARD: "CRITICAL",
    CORSIssueType.NULL_ORIGIN:          "HIGH",
    CORSIssueType.PREFLIGHT_MISCONFIG:  "MEDIUM",
    CORSIssueType.SUBDOMAIN_TRUST:      "HIGH",
    CORSIssueType.INSECURE_PROTOCOL:    "MEDIUM",
    CORSIssueType.SENSITIVE_DATA_CORS:  "HIGH",
    CORSIssueType.INSECURE_HEADERS:     "HIGH",
    CORSIssueType.JSON_API_CORS:        "HIGH",
}


# ── Scan configuration ───────────────────────────────────────────────────

@dataclass
class CORSScanConfig:
    """Tuneable parameters for a CORS scan run."""
    timeout: float = 8.0
    delay_between_requests: float = 0.05
    user_agent: str = "CORSAttackBot/1.0 (Prahaar_AI Security Scanner)"
    verify_ssl: bool = False
    verbose: bool = False


# ── CORS finding ─────────────────────────────────────────────────────────

@dataclass
class CORSFinding:
    """A single confirmed CORS misconfiguration."""
    issue_type: CORSIssueType
    severity: str
    endpoint: str
    method: str
    origin_sent: str
    acao_header: str                # Access-Control-Allow-Origin value
    acac_header: str = ""           # Access-Control-Allow-Credentials value
    acam_header: str = ""           # Access-Control-Allow-Methods value
    acah_header: str = ""           # Access-Control-Allow-Headers value
    content_type: str = ""          # Response Content-Type (for data exposure checks)
    impact: str = ""
    confidence: str = "CONFIRMED"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "vulnerability_type": "CORS Misconfiguration",
            "issue_type": self.issue_type.value,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "origin_sent": self.origin_sent,
            "response_headers": {
                "Access-Control-Allow-Origin": self.acao_header,
                "Access-Control-Allow-Credentials": self.acac_header,
                "Access-Control-Allow-Methods": self.acam_header,
                "Access-Control-Allow-Headers": self.acah_header,
            },
            "impact": self.impact,
            "confidence": self.confidence,
        }
        if self.content_type:
            d["response_headers"]["Content-Type"] = self.content_type
        return d


# ── Sensitive-data keywords for response body analysis ───────────────────

_SENSITIVE_KEYWORDS = {
    "user", "token", "email", "session", "profile", "account",
    "password", "secret", "credit", "ssn", "api_key", "auth",
}

# ── Default common paths to probe if no endpoints provided ──────────────

_COMMON_CORS_PATHS = [
    "/", "/api", "/api/user", "/api/users", "/api/data",
    "/api/config", "/api/status", "/login", "/profile",
    "/graphql", "/health",
]


# ── CORSAttackBot ────────────────────────────────────────────────────────

class CORSAttackBot:
    """
    CORS misconfiguration detection engine.

    Completely independent from the SQL injection and XSS pipelines.

    Stages
    ------
    1. For each endpoint, send requests with each test Origin header
    2. Analyze Access-Control-* response headers
    3. Send OPTIONS preflight requests
    4. Record all misconfigurations as findings
    """

    def __init__(
        self,
        target_url: str = "",
        config: Optional[CORSScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.config = config or CORSScanConfig()
        self._findings: List[CORSFinding] = []
        self._origins: List[str] = get_all_origins()

    # ── Public API ────────────────────────────────────────────────────

    def run_scan(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CORSFinding]:
        """
        Execute the full CORS scan.

        Parameters
        ----------
        endpoints : list[dict] | None
            Each dict: ``{"path": str, "method": str}``
            If None, the bot probes common API paths.

        Returns
        -------
        list[CORSFinding]
        """
        self._findings = []

        if not self.target_url:
            logger.warning("[CORSAttackBot] No target URL — skipping scan")
            return self._findings

        session = requests.Session()
        session.headers["User-Agent"] = self.config.user_agent
        session.verify = self.config.verify_ssl

        targets = endpoints or [{"path": p, "method": "GET"} for p in _COMMON_CORS_PATHS]

        if self.config.verbose:
            logger.info(
                "[CORSAttackBot] Scanning %d endpoints with %d origins",
                len(targets), len(self._origins),
            )

        # Deduplicate endpoints by path to avoid redundant testing
        seen_paths: set = set()

        for ep in targets:
            path = ep.get("path", "/")
            if path in seen_paths:
                continue
            seen_paths.add(path)

            method = ep.get("method", "GET").upper()
            url = self.target_url + path

            # ── Test each origin ──────────────────────────────────────
            for origin in self._origins:
                self._test_origin(session, url, path, method, origin)
                if self.config.delay_between_requests > 0:
                    time.sleep(self.config.delay_between_requests)

            # ── Preflight test (OPTIONS) ──────────────────────────────
            self._test_preflight(session, url, path)
            if self.config.delay_between_requests > 0:
                time.sleep(self.config.delay_between_requests)

        session.close()

        logger.info(
            "[CORSAttackBot] Scan complete — %d finding(s)", len(self._findings),
        )
        return self._findings

    def findings_summary(self) -> Dict[str, Any]:
        """Return a summary dict."""
        by_type: Dict[str, int] = {}
        for f in self._findings:
            key = f.issue_type.value
            by_type[key] = by_type.get(key, 0) + 1
        return {
            "total_cors_findings": len(self._findings),
            "by_type": by_type,
        }

    def get_findings_as_dicts(self) -> List[Dict[str, Any]]:
        """Return all findings as serializable dicts."""
        return [f.to_dict() for f in self._findings]

    # ── Internal: test a single origin against a URL ─────────────────

    def _test_origin(
        self,
        session: requests.Session,
        url: str,
        path: str,
        method: str,
        origin: str,
    ) -> None:
        """Send a request with the given Origin header and analyse response."""
        try:
            resp = session.request(
                method,
                url,
                headers={"Origin": origin},
                timeout=self.config.timeout,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[CORSAttackBot] Request failed %s %s: %s", method, url, exc)
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        content_type = resp.headers.get("Content-Type", "")

        if not acao:
            return  # No CORS headers → nothing to flag

        # ── 3. Credentials + Wildcard (CRITICAL — check first) ────────
        if acao == "*" and acac.lower() == "true":
            self._add_finding(
                CORSIssueType.CREDENTIALS_WILDCARD,
                path, method, origin, acao, acac,
                impact="Sensitive cookies or authentication tokens may be exposed to any origin.",
            )
            return  # Don't duplicate with plain wildcard

        # ── 1. Wildcard Origin ────────────────────────────────────────
        if acao == "*":
            self._add_finding(
                CORSIssueType.WILDCARD_ORIGIN,
                path, method, origin, acao, acac,
                impact="Any external website can access this API endpoint.",
            )
            # fall through to extended checks (don't return)

        # ── 4. Null Origin Acceptance ─────────────────────────────────
        elif origin == "null" and acao == "null":
            self._add_finding(
                CORSIssueType.NULL_ORIGIN,
                path, method, origin, acao, acac,
                impact="Attackers can exploit sandboxed iframes or file:// origins to access this endpoint.",
            )

        # ── 2. Origin Reflection ──────────────────────────────────────
        elif acao == origin:
            self._add_finding(
                CORSIssueType.ORIGIN_REFLECTION,
                path, method, origin, acao, acac,
                impact="Server reflects any Origin header, allowing attackers to bypass CORS restrictions.",
            )

        # ── Extended in-memory checks on the same response ────────────
        # These run without any additional network requests.

        # ── 6. Subdomain Trust Misconfiguration ──────────────────────
        if acao.startswith("*.") or (
            acao == origin and "." in origin
            and any(sub in origin for sub in ("sub.", "api.", "evil."))
        ):
            self._add_finding(
                CORSIssueType.SUBDOMAIN_TRUST,
                path, method, origin, acao, acac,
                impact="If an attacker controls a subdomain, they can bypass CORS restrictions.",
            )

        # ── 7. Insecure Protocol Trust ───────────────────────────────
        if origin.startswith("http://") and acao and (
            acao == origin or acao == "*"
        ):
            self._add_finding(
                CORSIssueType.INSECURE_PROTOCOL,
                path, method, origin, acao, acac,
                impact="Server accepts insecure HTTP origins, enabling downgrade attacks.",
            )

        # ── 8. Sensitive Data Exposure via CORS ──────────────────────
        if acao and acao != self.target_url:
            is_json = "application/json" in content_type.lower()
            if is_json:
                try:
                    body_text = resp.text[:4096].lower()
                except Exception:
                    body_text = ""
                if any(kw in body_text for kw in _SENSITIVE_KEYWORDS):
                    self._add_finding(
                        CORSIssueType.SENSITIVE_DATA_CORS,
                        path, method, origin, acao, acac,
                        impact="Endpoint returns sensitive JSON data and allows cross-origin access.",
                        content_type=content_type,
                    )

        # ── 10. Improper CORS with JSON APIs ─────────────────────────
        if acao == "*" and "application/json" in content_type.lower():
            self._add_finding(
                CORSIssueType.JSON_API_CORS,
                path, method, origin, acao, acac,
                impact="JSON API responses are readable from any website due to wildcard CORS.",
                content_type=content_type,
            )

    # ── Internal: preflight test ─────────────────────────────────────

    def _test_preflight(
        self,
        session: requests.Session,
        url: str,
        path: str,
    ) -> None:
        """Send an OPTIONS preflight request and check for overly permissive config."""
        try:
            resp = session.options(
                url,
                headers={
                    "Origin": "https://attacker.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                },
                timeout=self.config.timeout,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[CORSAttackBot] Preflight failed %s: %s", url, exc)
            return

        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if not acam and not acah:
            return  # No preflight config headers

        is_permissive_methods = acam == "*" or (
            acam and all(
                m.strip() in acam.upper()
                for m in ["GET", "POST", "PUT", "DELETE", "PATCH"]
            )
        )
        is_permissive_headers = acah == "*"

        if is_permissive_methods or is_permissive_headers:
            self._add_finding(
                CORSIssueType.PREFLIGHT_MISCONFIG,
                path, "OPTIONS", "https://attacker.com",
                acao, "",
                impact="Overly permissive preflight may allow unauthorized cross-origin requests.",
                acam=acam,
                acah=acah,
            )

        # ── 9. Insecure Allowed Headers ──────────────────────────────
        _DANGEROUS_HEADERS = {"authorization", "x-api-key", "cookie", "x-csrf-token"}
        if acah:
            acah_lower = acah.lower()
            if acah == "*" or any(h in acah_lower for h in _DANGEROUS_HEADERS):
                self._add_finding(
                    CORSIssueType.INSECURE_HEADERS,
                    path, "OPTIONS", "https://attacker.com",
                    acao, "",
                    impact="Dangerous headers (e.g. Authorization) are allowed in cross-origin requests.",
                    acam=acam,
                    acah=acah,
                )

    # ── Internal: add finding (with dedup) ───────────────────────────

    def _add_finding(
        self,
        issue_type: CORSIssueType,
        path: str,
        method: str,
        origin: str,
        acao: str,
        acac: str,
        impact: str,
        acam: str = "",
        acah: str = "",
        content_type: str = "",
    ) -> None:
        # Deduplicate: same issue type + endpoint = one finding
        for existing in self._findings:
            if existing.issue_type == issue_type and existing.endpoint == path:
                return

        self._findings.append(CORSFinding(
            issue_type=issue_type,
            severity=CORS_SEVERITY[issue_type],
            endpoint=path,
            method=method,
            origin_sent=origin,
            acao_header=acao,
            acac_header=acac,
            acam_header=acam,
            acah_header=acah,
            content_type=content_type,
            impact=impact,
        ))

        if self.config.verbose:
            logger.info(
                "[CORSAttackBot] FOUND: %s on %s (origin=%s, ACAO=%s)",
                issue_type.value, path, origin, acao,
            )
