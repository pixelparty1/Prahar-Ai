"""
report_generator.py
-------------------
Generates structured vulnerability reports in multiple formats:
  • JSON   – machine-readable, for pipelines
  • Text   – human-readable console output
  • Dict   – for programmatic consumption
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .response_analyzer import AnalysisResult, InjectionType, RiskLevel

import logging

logger = logging.getLogger(__name__)


# ── Remediation advice map ────────────────────────────────────────────────

REMEDIATION_MAP: Dict[InjectionType, str] = {
    InjectionType.AUTH_BYPASS:
        "Use parameterized queries or ORM prepared statements for all authentication queries.",
    InjectionType.DATA_EXTRACTION:
        "Use parameterized queries. Apply least-privilege database permissions. Never expose raw query results.",
    InjectionType.DB_INFO:
        "Use parameterized queries. Restrict access to information_schema / system tables.",
    InjectionType.TIME_BASED:
        "Use parameterized queries. Implement query timeouts and rate-limiting.",
    InjectionType.BOOLEAN_BASED:
        "Use parameterized queries. Avoid exposing conditional differences in responses.",
    InjectionType.ERROR_BASED:
        "Use parameterized queries. Disable detailed SQL error messages in production.",
    InjectionType.PRIVILEGE_ESCALATION:
        "Use parameterized queries. Apply least-privilege DB roles. Disable stacked queries if possible.",
    InjectionType.DATA_MODIFICATION:
        "Use parameterized queries. Restrict UPDATE permissions to only necessary tables/roles.",
    InjectionType.DATA_DELETION:
        "Use parameterized queries. Restrict DELETE permissions. Enable soft-delete patterns.",
    InjectionType.DATA_INSERTION:
        "Use parameterized queries. Validate all input server-side before insertion.",
    InjectionType.TABLE_DROP:
        "Use parameterized queries. NEVER grant DROP privileges to application database users.",
}


# ── Report builder ────────────────────────────────────────────────────────

class ReportGenerator:
    """Aggregates ``AnalysisResult`` objects and produces reports."""

    def __init__(self):
        self.results: List[AnalysisResult] = []
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None
        self.target: str = ""
        self.static_findings: List[Dict] = []

    def set_target(self, target: str) -> None:
        self.target = target

    def mark_start(self) -> None:
        self.scan_start = datetime.now(timezone.utc)

    def mark_end(self) -> None:
        self.scan_end = datetime.now(timezone.utc)

    def add_result(self, result: AnalysisResult) -> None:
        self.results.append(result)

    def add_results(self, results: List[AnalysisResult]) -> None:
        self.results.extend(results)

    def add_static_findings(self, findings: List[Dict]) -> None:
        self.static_findings.extend(findings)

    # ── Aggregate helpers ─────────────────────────────────────────────

    @property
    def vulnerable_results(self) -> List[AnalysisResult]:
        return [r for r in self.results if r.vulnerable]

    @property
    def overall_risk(self) -> RiskLevel:
        if not self.vulnerable_results:
            return RiskLevel.SAFE
        levels = [r.risk_level for r in self.vulnerable_results]
        order = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return max(levels, key=lambda l: order.index(l))

    @property
    def all_injection_types(self) -> List[InjectionType]:
        types: List[InjectionType] = []
        for r in self.vulnerable_results:
            for t in r.injection_types:
                if t not in types:
                    types.append(t)
        return types

    # ── Dict report ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return the full report as a nested dictionary."""
        vuln_endpoints: Dict[str, Dict] = {}

        for r in self.vulnerable_results:
            key = f"{r.endpoint}|{r.parameter}"
            if key not in vuln_endpoints:
                vuln_endpoints[key] = {
                    "endpoint": r.endpoint,
                    "parameter": r.parameter,
                    "vulnerability": "SQL Injection",
                    "risk_level": RiskLevel.SAFE.value,
                    "possible_attacks": [],
                    "payloads_used": [],
                    "evidence": [],
                    "database_hint": None,
                    "recommended_fixes": [],
                }

            entry = vuln_endpoints[key]

            # Merge injection types
            for itype in r.injection_types:
                if itype.value not in entry["possible_attacks"]:
                    entry["possible_attacks"].append(itype.value)
                fix = REMEDIATION_MAP.get(itype, "")
                if fix and fix not in entry["recommended_fixes"]:
                    entry["recommended_fixes"].append(fix)

            # Merge evidence
            entry["evidence"].extend(r.evidence)

            # Track payloads
            if r.payload_used and r.payload_used not in entry["payloads_used"]:
                entry["payloads_used"].append(r.payload_used)

            # Update risk level (keep the highest)
            order = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            existing = RiskLevel(entry["risk_level"])
            if order.index(r.risk_level) > order.index(existing):
                entry["risk_level"] = r.risk_level.value

            if r.database_hint:
                entry["database_hint"] = r.database_hint

        # Deduplicate recommended_fixes to a single string when only one
        for entry in vuln_endpoints.values():
            if len(entry["recommended_fixes"]) == 1:
                entry["recommended_fix"] = entry["recommended_fixes"][0]
            elif entry["recommended_fixes"]:
                entry["recommended_fix"] = " ".join(dict.fromkeys(entry["recommended_fixes"]))
            else:
                entry["recommended_fix"] = "Use parameterized queries or ORM prepared statements."
            del entry["recommended_fixes"]

        duration = None
        if self.scan_start and self.scan_end:
            duration = (self.scan_end - self.scan_start).total_seconds()

        return {
            "scan_summary": {
                "target": self.target,
                "scan_time_utc": self.scan_start.isoformat() if self.scan_start else None,
                "duration_seconds": duration,
                "total_payloads_tested": len(self.results),
                "vulnerabilities_found": len(vuln_endpoints),
                "overall_risk_level": self.overall_risk.value,
            },
            "vulnerabilities": list(vuln_endpoints.values()),
            "static_analysis_findings": self.static_findings if self.static_findings else [],
        }

    # ── JSON report ───────────────────────────────────────────────────

    def to_json(self, indent: int = 2) -> str:
        """Return the report as a pretty-printed JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, filepath: str) -> str:
        """Write the JSON report to a file. Returns the file path."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        logger.info("Report saved to %s", filepath)
        return filepath

    # ── Human-readable text report ────────────────────────────────────

    def to_text(self) -> str:
        """Return a nicely formatted text report for console output."""
        lines: List[str] = []
        sep = "=" * 70

        lines.append(sep)
        lines.append("  SQL INJECTION VULNERABILITY SCAN REPORT")
        lines.append(sep)
        lines.append(f"  Target    : {self.target}")
        if self.scan_start:
            lines.append(f"  Scan Time : {self.scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if self.scan_start and self.scan_end:
            dur = (self.scan_end - self.scan_start).total_seconds()
            lines.append(f"  Duration  : {dur:.1f}s")
        lines.append(f"  Payloads  : {len(self.results)} tested")
        lines.append(f"  Overall   : {self.overall_risk.value}")
        lines.append(sep)

        if not self.vulnerable_results:
            lines.append("")
            lines.append("  ✅  No SQL Injection vulnerabilities detected.")
            lines.append("")
            lines.append(sep)
            return "\n".join(lines)

        report_dict = self.to_dict()
        for vuln in report_dict["vulnerabilities"]:
            lines.append("")
            lines.append(f"  ⚠  SQL Injection Vulnerability Detected")
            lines.append(f"  {'─' * 46}")
            lines.append(f"  Endpoint  : {vuln['endpoint']}")
            lines.append(f"  Parameter : {vuln['parameter']}")
            lines.append(f"  Risk Level: {vuln['risk_level']}")
            if vuln.get("database_hint"):
                lines.append(f"  Database  : {vuln['database_hint']}")
            lines.append("")
            lines.append("  Possible Attacks:")
            for atk in vuln["possible_attacks"]:
                lines.append(f"    • {atk}")
            lines.append("")
            lines.append("  Payloads Used:")
            for p in vuln["payloads_used"][:10]:  # limit display
                lines.append(f"    → {p}")
            if len(vuln["payloads_used"]) > 10:
                lines.append(f"    ... and {len(vuln['payloads_used']) - 10} more")
            lines.append("")
            lines.append(f"  Recommended Fix:")
            lines.append(f"    {vuln.get('recommended_fix', 'Use parameterized queries.')}")
            lines.append("")
            lines.append(f"  Evidence:")
            for ev in vuln["evidence"][:8]:
                lines.append(f"    - {ev}")
            if len(vuln["evidence"]) > 8:
                lines.append(f"    ... and {len(vuln['evidence']) - 8} more")
            lines.append("")
            lines.append(sep)

        # Static analysis findings
        if self.static_findings:
            lines.append("")
            lines.append("  STATIC CODE ANALYSIS FINDINGS")
            lines.append(f"  {'─' * 46}")
            for f in self.static_findings:
                lines.append(f"    File: {f['file']}  Line: {f['line']}")
                lines.append(f"    Issue: {f['issue']}")
                lines.append(f"    Code: {f['code'][:100]}")
                lines.append("")
            lines.append(sep)

        return "\n".join(lines)

    def print_report(self) -> None:
        """Print the text report to stdout."""
        print(self.to_text())
