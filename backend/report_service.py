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
        self._crawled_endpoints: List[Dict] = []
        self._pipeline_events: List[Dict] = []
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

        vuln_count = len(vulnerabilities)
        static_count = len(deduped_static)

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
                "total_static_findings": static_count,
                "total_endpoints_crawled": len(self._crawled_endpoints),
            },
            "vulnerabilities": vulnerabilities,
            "static_analysis_findings": deduped_static,
            "crawled_endpoints": self._crawled_endpoints,
            "pipeline_events": self._pipeline_events,
        }

        logger.info(
            "[ReportService] Report built — %d vulns, %d static findings, risk=%s",
            vuln_count,
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
            f"  Vulnerabilities found   : {s.get('total_vulnerabilities', 0)}",
            f"  Static-analysis issues  : {s.get('total_static_findings', 0)}",
            f"  Endpoints crawled       : {s.get('total_endpoints_crawled', 0)}",
            f"  Payloads tested         : {s.get('total_payloads_tested', 0)}",
            "═" * 60,
        ]

        vulns = d.get("vulnerabilities", [])
        if vulns:
            lines.append("  VULNERABILITIES:")
            for i, v in enumerate(vulns, 1):
                lines.append(
                    f"    {i}. [{v.get('risk_level','?')}] {v.get('endpoint','?')} "
                    f"param={v.get('parameter','?')} — {v.get('vulnerability','?')}"
                )
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
