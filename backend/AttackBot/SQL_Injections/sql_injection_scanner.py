"""
sql_injection_scanner.py
------------------------
Main orchestrator that ties together:
  • EndpointFinder   – discovers injectable endpoints
  • PayloadLibrary   – provides categorized attack payloads
  • ResponseAnalyzer – compares baseline/injected responses
  • ReportGenerator  – produces final reports

Usage
-----
    from AttackBot import SQLInjectionAttackBot

    bot = SQLInjectionAttackBot(target_url="http://localhost:5000")
    bot.discover_endpoints(project_dir="path/to/project")
    report = bot.run_scan()
    report.print_report()
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from .endpoint_finder import DiscoveredEndpoint, EndpointFinder, probe_live_endpoints
from .payload_library import (
    ALL_CATEGORIES,
    AUTH_BYPASS_PAYLOADS,
    BOOLEAN_PAYLOADS,
    DATA_DELETION_PAYLOADS,
    DATA_INSERT_PAYLOADS,
    DB_INFO_PAYLOADS,
    ERROR_BASED_PAYLOADS,
    PRIVILEGE_ESCALATION_PAYLOADS,
    TABLE_DROP_PAYLOADS,
    TIME_BASED_PAYLOADS,
    UNION_PAYLOADS,
    PayloadCategory,
)
from .report_generator import ReportGenerator
from .response_analyzer import (
    AnalysisResult,
    InjectionType,
    ResponseAnalyzer,
    RiskLevel,
    StaticCodeAnalyzer,
)

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Tuneable parameters for a scan run."""
    timeout: float = 10.0           # HTTP request timeout (seconds)
    delay_between_requests: float = 0.1  # polite delay between requests
    max_payloads_per_category: int = 0   # 0 = unlimited
    skip_time_based: bool = False   # skip slow time-based tests
    skip_destructive_sim: bool = False  # skip UPDATE/DELETE/DROP sim
    user_agent: str = "SQLInjectionAttackBot/1.0 (Security Scanner)"
    verify_ssl: bool = False
    follow_redirects: bool = False
    verbose: bool = True


# ── Scan log entry ────────────────────────────────────────────────────────

@dataclass
class ScanLogEntry:
    """One entry in the scan audit log."""
    timestamp: float
    endpoint: str
    parameter: str
    payload: str
    category: str
    status_code: int
    response_time: float
    vulnerable: bool

    def __str__(self):
        flag = "VULN" if self.vulnerable else "safe"
        return (
            f"[{self.timestamp:.0f}] {flag:4s} | {self.endpoint:20s} | "
            f"param={self.parameter:12s} | {self.category:30s} | {self.payload[:40]}"
        )


# ── Main SQLInjectionAttackBot class ─────────────────────────────────────

class SQLInjectionAttackBot:
    """
    Modular SQL Injection attack simulation engine.

    Stages
    ------
    1. Endpoint Discovery   →  ``discover_endpoints()``
    2. Payload Injection     →  ``run_scan()``
    3. Response Analysis     →  (automatic inside run_scan)
    4. Exploit Simulation    →  (automatic inside run_scan)
    5. Risk Scoring          →  (automatic inside run_scan)
    6. Report Generation     →  ``get_report()``
    """

    def __init__(
        self,
        target_url: str = "",
        config: Optional[ScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.config = config or ScanConfig()

        # Sub-modules
        self._analyzer = ResponseAnalyzer()
        self._report = ReportGenerator()
        self._static_analyzer = StaticCodeAnalyzer()

        # State
        self.endpoints: List[DiscoveredEndpoint] = []
        self.scan_log: List[ScanLogEntry] = []
        self._session: Optional[requests.Session] = None

    # ── 1. Endpoint Discovery ─────────────────────────────────────────

    def discover_endpoints(
        self,
        project_dir: Optional[str] = None,
        extra_endpoints: Optional[List[DiscoveredEndpoint]] = None,
        probe_live: bool = True,
    ) -> List[DiscoveredEndpoint]:
        """
        Discover endpoints from:
          • static analysis of project files
          • live URL probing
          • manually supplied endpoints
        """
        discovered: List[DiscoveredEndpoint] = []

        # Static file analysis
        if project_dir:
            finder = EndpointFinder(project_dir)
            discovered.extend(finder.scan())
            logger.info("Static analysis found %d endpoints.", len(discovered))

            # Also run static code analysis
            static_findings = self._static_analyzer.analyze_directory(project_dir)
            self._report.add_static_findings(static_findings)

        # Live probing
        if probe_live and self.target_url:
            live = probe_live_endpoints(self.target_url, timeout=self.config.timeout)
            discovered.extend(live)

        # Manual additions
        if extra_endpoints:
            discovered.extend(extra_endpoints)

        # Deduplicate
        seen = set()
        for ep in discovered:
            key = (ep.path, ep.method, tuple(ep.parameters))
            if key not in seen:
                seen.add(key)
                self.endpoints.append(ep)

        logger.info("Total unique endpoints: %d", len(self.endpoints))
        return self.endpoints

    def add_endpoint(
        self,
        path: str,
        method: str = "POST",
        parameters: Optional[List[str]] = None,
    ) -> None:
        """Manually add an endpoint to scan."""
        self.endpoints.append(
            DiscoveredEndpoint(path=path, method=method.upper(), parameters=parameters or [])
        )

    # ── 2–5. Full Scan ────────────────────────────────────────────────

    def run_scan(
        self,
        categories: Optional[List[PayloadCategory]] = None,
    ) -> ReportGenerator:
        """
        Execute the full scan pipeline:
          • Send baseline requests
          • Inject payloads from every category
          • Analyze responses
          • Produce report
        """
        if not self.endpoints:
            logger.warning("No endpoints to scan. Run discover_endpoints() first or add manually.")
            return self._report

        if not self.target_url:
            logger.error("No target_url configured. Cannot perform live scan.")
            return self._report

        self._session = requests.Session()
        self._session.headers["User-Agent"] = self.config.user_agent
        self._session.verify = self.config.verify_ssl

        self._report.set_target(self.target_url)
        self._report.mark_start()

        cats = categories or self._get_active_categories()

        for ep in self.endpoints:
            if not ep.parameters:
                # If no parameters known, try a generic "input" parameter
                ep.parameters = ["input"]

            for param in ep.parameters:
                self._scan_parameter(ep, param, cats)

        self._report.mark_end()
        self._session.close()
        self._session = None

        if self.config.verbose:
            self._report.print_report()

        return self._report

    # ── Scan a single parameter ───────────────────────────────────────

    def _scan_parameter(
        self,
        endpoint: DiscoveredEndpoint,
        parameter: str,
        categories: List[PayloadCategory],
    ) -> None:
        """Inject every payload into a single parameter of an endpoint."""
        url = f"{self.target_url}{endpoint.path}"

        # 1. Send a baseline (benign) request
        baseline_body, baseline_status, baseline_time = self._send_request(
            url, endpoint.method, parameter, "test_normal_value"
        )
        if baseline_body is None:
            logger.warning("Baseline request failed for %s param=%s", endpoint.path, parameter)
            return

        # 2. Loop through each category's payloads
        for category in categories:
            payloads = category.payloads
            if self.config.max_payloads_per_category > 0:
                payloads = payloads[: self.config.max_payloads_per_category]

            for payload in payloads:
                inj_body, inj_status, inj_time = self._send_request(
                    url, endpoint.method, parameter, payload
                )
                if inj_body is None:
                    continue

                # 3. Analyze the response
                result = self._analyzer.analyze(
                    baseline_body=baseline_body,
                    baseline_status=baseline_status,
                    baseline_time=baseline_time,
                    injected_body=inj_body,
                    injected_status=inj_status,
                    injected_time=inj_time,
                    payload=payload,
                    endpoint=endpoint.path,
                    parameter=parameter,
                    category=category.name,
                )

                # 4. Log and store
                log_entry = ScanLogEntry(
                    timestamp=time.time(),
                    endpoint=endpoint.path,
                    parameter=parameter,
                    payload=payload,
                    category=category.name,
                    status_code=inj_status,
                    response_time=inj_time,
                    vulnerable=result.vulnerable,
                )
                self.scan_log.append(log_entry)
                self._report.add_result(result)

                if result.vulnerable and self.config.verbose:
                    logger.info("VULNERABLE: %s", log_entry)

                time.sleep(self.config.delay_between_requests)

    # ── HTTP request helper ───────────────────────────────────────────

    def _send_request(
        self,
        url: str,
        method: str,
        parameter: str,
        value: str,
    ) -> Tuple[Optional[str], int, float]:
        """
        Send a single HTTP request and return (body, status, elapsed_seconds).
        Returns (None, 0, 0) on failure.
        """
        assert self._session is not None

        try:
            start = time.time()
            if method.upper() in ("GET", "HEAD", "OPTIONS"):
                resp = self._session.request(
                    method,
                    url,
                    params={parameter: value},
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects,
                )
            else:
                resp = self._session.request(
                    method,
                    url,
                    data={parameter: value},
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects,
                )
            elapsed = time.time() - start
            return resp.text, resp.status_code, elapsed
        except requests.RequestException as exc:
            logger.debug("Request failed (%s %s param=%s): %s", method, url, parameter, exc)
            return None, 0, 0.0

    # ── Category selection helpers ────────────────────────────────────

    def _get_active_categories(self) -> List[PayloadCategory]:
        """Return the list of categories to use based on config."""
        cats = list(ALL_CATEGORIES)
        if self.config.skip_time_based:
            cats = [c for c in cats if c.name != TIME_BASED_PAYLOADS.name]
        if self.config.skip_destructive_sim:
            cats = [c for c in cats if c.name not in (
                PRIVILEGE_ESCALATION_PAYLOADS.name,
                DATA_DELETION_PAYLOADS.name,
                TABLE_DROP_PAYLOADS.name,
                DATA_INSERT_PAYLOADS.name,
            )]
        return cats

    # ── Report accessors ──────────────────────────────────────────────

    def get_report(self) -> ReportGenerator:
        """Return the ReportGenerator for further processing."""
        return self._report

    def get_json_report(self) -> str:
        """Return the scan report as JSON."""
        return self._report.to_json()

    def get_text_report(self) -> str:
        """Return the scan report as formatted text."""
        return self._report.to_text()

    def save_report(self, filepath: str) -> str:
        """Save the scan report to a JSON file."""
        return self._report.save_json(filepath)

    def get_scan_log(self) -> List[ScanLogEntry]:
        """Return the full audit log of every payload tested."""
        return self.scan_log

    # ── Static-only scan (no live server required) ────────────────────

    def static_scan(self, project_dir: str) -> ReportGenerator:
        """
        Perform a static-only scan of project source code.
        No live server needed — only looks for unsafe SQL patterns.
        """
        self._report.set_target(project_dir)
        self._report.mark_start()

        findings = self._static_analyzer.analyze_directory(project_dir)
        self._report.add_static_findings(findings)

        # Also discover endpoints statically
        finder = EndpointFinder(project_dir)
        endpoints = finder.scan()
        self.endpoints = endpoints

        self._report.mark_end()

        if self.config.verbose:
            self._report.print_report()

        return self._report

    # ── Convenience: quick scan ───────────────────────────────────────

    @classmethod
    def quick_scan(
        cls,
        target_url: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        project_dir: Optional[str] = None,
        save_to: Optional[str] = None,
    ) -> ReportGenerator:
        """
        One-liner convenience method.

        Parameters
        ----------
        target_url : str
            Base URL of the target (e.g. "http://localhost:5000").
        endpoints : list[dict], optional
            Manual endpoints: [{"path": "/login", "method": "POST", "parameters": ["username","password"]}]
        project_dir : str, optional
            Path to upload project source code for static analysis.
        save_to : str, optional
            File path to save the JSON report.

        Returns
        -------
        ReportGenerator
        """
        bot = cls(target_url=target_url)

        # Discover from project files
        extra = []
        if endpoints:
            for ep in endpoints:
                extra.append(DiscoveredEndpoint(
                    path=ep["path"],
                    method=ep.get("method", "POST"),
                    parameters=ep.get("parameters", []),
                ))
        bot.discover_endpoints(project_dir=project_dir, extra_endpoints=extra, probe_live=True)

        report = bot.run_scan()

        if save_to:
            bot.save_report(save_to)

        return report
