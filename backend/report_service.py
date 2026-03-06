"""
report_service.py  –  Module 9
-------------------------------
Structured report generator that merges live-scan results, static-analysis
findings, and crawl metadata into a single unified report.

Consumes output from:
  • AttackBotRunner  (live scan → ReportGenerator)
  • StaticScanRunner (static analysis)
  • Crawler          (endpoint inventory)

Exports as JSON (dict / string / file).  Does NOT modify any AttackBot code.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportService:
    """
    Combines results from every stage of the pipeline into a single
    structured report.

    Usage
    -----
    >>> svc = ReportService(target_url="http://127.0.0.1:9000")
    >>> svc.set_live_scan_report(runner_result["report"])  # ReportGenerator
    >>> svc.set_static_findings(static_result["findings"])
    >>> svc.set_crawled_endpoints(endpoints_list)
    >>> report_dict = svc.build()
    >>> svc.save_json("report.json")
    """

    def __init__(self, target_url: str = "", upload_id: str = ""):
        self._target_url = target_url
        self._upload_id = upload_id
        self._live_report_dict: Optional[Dict] = None
        self._static_findings: List[Dict] = []
        self._xss_findings: List[Dict] = []
        self._cors_findings: List[Dict] = []
        self._ddos_findings: List[Dict] = []
        self._crawled_endpoints: List[Dict] = []
        self._pipeline_events: List[Dict] = []
        self._sandbox_status: Dict = {}
        self._built: Optional[Dict] = None

    # ── Setters (called by scan_controller) ───────────────────────────

    def set_live_scan_report(self, report_generator) -> None:
        """
        Accept a ReportGenerator instance (from AttackBotRunner) and
        extract its dict representation.
        """
        if report_generator is None:
            return
        try:
            self._live_report_dict = report_generator.to_dict()
        except Exception:
            # Fallback: maybe we received a plain dict already
            if isinstance(report_generator, dict):
                self._live_report_dict = report_generator

    def set_static_findings(self, findings: List[Dict]) -> None:
        self._static_findings = findings or []

    def set_crawled_endpoints(self, endpoints: List[Dict]) -> None:
        """Accept the crawled endpoints as a list of dicts."""
        self._crawled_endpoints = endpoints or []

    def set_xss_findings(self, findings: List[Dict]) -> None:
        """Accept XSS findings produced by XSSRunner."""
        self._xss_findings = findings or []

    def set_cors_findings(self, findings: List[Dict]) -> None:
        """Accept CORS misconfiguration findings produced by CORSRunner."""
        self._cors_findings = findings or []

    def set_ddos_findings(self, findings: List[Dict]) -> None:
        """Accept DDoS vulnerability findings produced by DDoSRunner."""
        self._ddos_findings = findings or []

    def set_sandbox_status(
        self,
        success: bool,
        target_url: str = "",
        error: str = "",
        logs: List[str] = None,
        fallback: str = "Static code analysis performed instead.",
    ) -> None:
        """Record sandbox launch outcome for the report."""
        self._sandbox_status = {
            "success": success,
            "target_url": target_url,
            "error": error,
            "logs": (logs or [])[-20:],   # keep last 20 log lines
            "fallback": "" if success else fallback,
        }

    def add_event(self, stage: str, message: str, success: bool = True) -> None:
        """Record a pipeline event (for audit / debugging)."""
        self._pipeline_events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "message": message,
            "success": success,
        })

    # ── Build ─────────────────────────────────────────────────────────

    def build(self) -> Dict[str, Any]:
        """
        Merge every data source into the final report dict.

        Structure
        ---------
        {
            "meta": { ... },
            "scan_summary": { ... },
            "vulnerabilities": [ ... ],
            "static_analysis_findings": [ ... ],
            "crawled_endpoints": [ ... ],
            "pipeline_events": [ ... ],
        }
        """
        live = self._live_report_dict or {}

        scan_summary = live.get("scan_summary", {})
        vulnerabilities = live.get("vulnerabilities", [])
        static_from_live = live.get("static_analysis_findings", [])

        # Merge static findings (from live scan + from StaticScanRunner)
        all_static = list(static_from_live) + list(self._static_findings)
        # Deduplicate by (file, line, issue)
        seen = set()
        deduped_static: List[Dict] = []
        for f in all_static:
            key = (f.get("file", ""), f.get("line", 0), f.get("issue", ""))
            if key not in seen:
                seen.add(key)
                deduped_static.append(f)

        # Derive overall risk
        overall_risk = scan_summary.get("overall_risk_level", "SAFE")
        if not overall_risk or overall_risk == "SAFE":
            if deduped_static:
                severities = {f.get("severity", "").upper() for f in deduped_static}
                if "CRITICAL" in severities:
                    overall_risk = "CRITICAL"
                elif "HIGH" in severities:
                    overall_risk = "HIGH"
                elif "MEDIUM" in severities:
                    overall_risk = "MEDIUM"
                elif "LOW" in severities:
                    overall_risk = "LOW"

        vuln_count   = len(vulnerabilities)
        static_count = len(deduped_static)

        # Normalize and deduplicate XSS findings (Improvement 5)
        xss_seen: set = set()
        deduped_xss: List[Dict] = []
        for f in self._xss_findings:
            key = (f.get("endpoint", ""), f.get("parameter", ""), f.get("xss_type", ""))
            if key not in xss_seen:
                xss_seen.add(key)
                deduped_xss.append(f)

        # Normalize and deduplicate CORS findings (Improvement 5)
        cors_seen: set = set()
        deduped_cors: List[Dict] = []
        for f in self._cors_findings:
            key = (f.get("endpoint", ""), f.get("issue_type", ""), f.get("origin_sent", ""))
            if key not in cors_seen:
                cors_seen.add(key)
                deduped_cors.append(f)

        xss_count    = len(deduped_xss)
        cors_count   = len(deduped_cors)

        # Normalize and deduplicate DDoS findings
        ddos_seen: set = set()
        deduped_ddos: List[Dict] = []
        for f in self._ddos_findings:
            key = (f.get("endpoint", ""), f.get("attack_type", ""))
            if key not in ddos_seen:
                ddos_seen.add(key)
                deduped_ddos.append(f)

        ddos_count   = len(deduped_ddos)

        # Escalate overall risk based on XSS, CORS, and DDoS findings
        order = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for findings_list in (deduped_xss, deduped_cors, deduped_ddos):
            if findings_list:
                severities = {f.get("severity", "").upper() for f in findings_list}
                max_sev = max(severities, key=lambda s: order.index(s) if s in order else 0)
                if overall_risk in order and max_sev in order:
                    if order.index(max_sev) > order.index(overall_risk):
                        overall_risk = max_sev

        self._built = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "upload_id": self._upload_id,
                "target_url": self._target_url,
                "generator": "Prahaar_AI ReportService v1.0",
            },
            "scan_summary": {
                **scan_summary,
                "overall_risk_level": overall_risk,
                "total_vulnerabilities": vuln_count,
                "total_xss_vulnerabilities": xss_count,
                "total_cors_misconfigurations": cors_count,
                "total_ddos_vulnerabilities": ddos_count,
                "total_static_findings": static_count,
                "total_endpoints_crawled": len(self._crawled_endpoints),
            },
            "vulnerabilities": vulnerabilities,
            "xss_vulnerabilities": deduped_xss,
            "cors_vulnerabilities": deduped_cors,
            "ddos_vulnerabilities": deduped_ddos,
            "static_analysis_findings": deduped_static,
            "crawled_endpoints": self._crawled_endpoints,
            "live_scan_status": self._sandbox_status,
            "pipeline_events": self._pipeline_events,
        }

        logger.info(
            "[ReportService] Report built — %d SQL vulns, %d XSS findings, %d CORS findings, %d DDoS findings, %d static, risk=%s",
            vuln_count,
            xss_count,
            cors_count,
            ddos_count,
            static_count,
            overall_risk,
        )
        return self._built

    # ── Export helpers ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return the built report as a dict (calls build() if needed)."""
        if self._built is None:
            self.build()
        return self._built  # type: ignore[return-value]

    def to_json(self, indent: int = 2) -> str:
        """Return the report as a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, filepath: str) -> str:
        """Write the report to a JSON file. Returns the filepath."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        logger.info("[ReportService] Report saved → %s", filepath)
        return filepath

    # ── Human-readable summary ────────────────────────────────────────

    def summary_text(self) -> str:
        """Return a concise multi-line summary suitable for CLI output."""
        d = self.to_dict()
        s = d.get("scan_summary", {})
        lines = [
            "═" * 60,
            "  PRAHAAR AI — SCAN REPORT SUMMARY",
            "═" * 60,
            f"  Target       : {d['meta'].get('target_url', 'N/A')}",
            f"  Generated    : {d['meta'].get('generated_at', 'N/A')}",
            f"  Upload ID    : {d['meta'].get('upload_id', 'N/A')}",
            "─" * 60,
            f"  Overall Risk : {s.get('overall_risk_level', 'UNKNOWN')}",
            f"  SQL Injection vulns     : {s.get('total_vulnerabilities', 0)}",
            f"  XSS vulnerabilities     : {s.get('total_xss_vulnerabilities', 0)}",
            f"  CORS misconfigurations  : {s.get('total_cors_misconfigurations', 0)}",
            f"  DDoS vulnerabilities    : {s.get('total_ddos_vulnerabilities', 0)}",
            f"  Static-analysis issues  : {s.get('total_static_findings', 0)}",
            f"  Endpoints crawled       : {s.get('total_endpoints_crawled', 0)}",
            f"  Payloads tested         : {s.get('total_payloads_tested', 0)}",
            "═" * 60,
        ]

        # Live scan status block (Issue 3)
        sb = d.get("live_scan_status", {})
        if sb:
            lines.append("  LIVE SCAN STATUS:")
            if sb.get("success"):
                lines.append(f"    Sandbox running at: {sb.get('target_url', 'N/A')}")
            else:
                lines.append(f"    Sandbox server could not start.")
                if sb.get("error"):
                    lines.append(f"    Reason  : {sb['error']}")
                if sb.get("fallback"):
                    lines.append(f"    Fallback: {sb['fallback']}")
                if sb.get("logs"):
                    lines.append("    Server logs:")
                    for ln in sb["logs"][-5:]:
                        lines.append(f"      {ln}")
            lines.append("─" * 60)

        vulns = d.get("vulnerabilities", [])
        if vulns:
            lines.append("  VULNERABILITIES:")
            for i, v in enumerate(vulns, 1):
                lines.append(
                    f"    {i}. [{v.get('risk_level','?')}] {v.get('endpoint','?')} "
                    f"param={v.get('parameter','?')} — {v.get('vulnerability','?')}"
                )
            lines.append("─" * 60)

        xss_vulns = d.get("xss_vulnerabilities", [])
        if xss_vulns:
            lines.append("  XSS VULNERABILITIES:")
            for i, v in enumerate(xss_vulns, 1):
                lines.append(
                    f"    {i}. [{v.get('severity','?')}] {v.get('xss_type','?')} "
                    f"— {v.get('endpoint','?')} param={v.get('parameter','?')} "
                    f"({v.get('confidence','?')})"
                )
            lines.append("─" * 60)

        cors_vulns = d.get("cors_vulnerabilities", [])
        if cors_vulns:
            lines.append("  CORS MISCONFIGURATIONS:")
            for i, v in enumerate(cors_vulns, 1):
                lines.append(
                    f"    {i}. [{v.get('severity','?')}] {v.get('issue_type','?')} "
                    f"— {v.get('endpoint','?')} origin={v.get('origin_sent','?')} "
                    f"({v.get('confidence','?')})"
                )
            lines.append("─" * 60)

        ddos_vulns = d.get("ddos_vulnerabilities", [])
        if ddos_vulns:
            lines.append("  DDOS VULNERABILITIES:")
            for i, v in enumerate(ddos_vulns, 1):
                lines.append(
                    f"    {i}. [{v.get('severity','?')}] {v.get('attack_type','?')} "
                    f"— {v.get('endpoint','?')}"
                )
                if v.get('observation'):
                    lines.append(f"       {v['observation'][:120]}")
            lines.append("─" * 60)

        static = d.get("static_analysis_findings", [])
        if static:
            lines.append("  STATIC FINDINGS:")
            for i, f in enumerate(static[:10], 1):
                lines.append(
                    f"    {i}. [{f.get('severity','?')}] {f.get('file','?')}:{f.get('line','?')} "
                    f"— {f.get('issue','?')}"
                )
            if len(static) > 10:
                lines.append(f"    … and {len(static) - 10} more")
            lines.append("─" * 60)

        lines.append("")
        return "\n".join(lines)
