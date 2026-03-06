"""
xss_defense_bot.py
------------------
Top-level façade that wires together the XSS defense monitor, rules,
and response engine.

Usage:
    bot = XSSDefenseBot(target_url="https://example.com")
    results = bot.analyze_findings(findings_dicts, as_dicts=True)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .xss_defense_monitor import XSSDefenseMonitor
from .xss_defense_response import XSSDefenseEngine
from .xss_defense_rules import ALL_XSS_DEFENSE_RULES, XSSDefenseRule


class XSSDefenseBot:
    """
    Analyses XSS findings produced by the XSSAttackBot and simulates
    realistic security defences against each finding.
    """

    def __init__(
        self,
        target_url: str = "",
        rules: Optional[List[XSSDefenseRule]] = None,
    ) -> None:
        self.target_url = target_url
        self._monitor = XSSDefenseMonitor()
        self._engine = XSSDefenseEngine(rules or list(ALL_XSS_DEFENSE_RULES))
        self._results: List[Dict[str, Any]] = []
        self._battle_log: List[str] = []
        self._start_time: Optional[float] = None

    # ── public API ────────────────────────────────────────────────────

    def analyze_findings(
        self,
        findings_dicts: List[Dict[str, Any]],
        as_dicts: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Process a list of finding dicts from XSSRunner.

        Returns a list of verdict dicts (if *as_dicts* is True) or
        XSSDefenseVerdict objects.
        """
        self._start_time = time.time()
        events = self._monitor.process_findings(findings_dicts)

        results = []
        for evt in events:
            verdict = self._engine.evaluate(evt)
            entry = verdict.to_dict() if as_dicts else verdict
            results.append(entry)
            self._results.append(verdict.to_dict())

            # Build battle log entry
            status = "MITIGATED" if verdict.blocked else "ALLOWED"
            self._battle_log.append(
                f"[{status}] {evt.xss_type} @ {evt.endpoint} "
                f"param={evt.parameter} → {verdict.action.value}"
                f"{(' via ' + verdict.technique.value) if verdict.technique else ''}"
            )

        return results

    def get_results(self) -> Dict[str, Any]:
        summary = self._engine.get_summary()
        summary["target_url"] = self.target_url
        summary["attack_breakdown"] = self._monitor.rate_tracker.get_breakdown()
        if self._start_time:
            summary["analysis_time_ms"] = round(
                (time.time() - self._start_time) * 1000, 1
            )
        return {
            "success": True,
            "target_url": self.target_url,
            "verdicts": list(self._results),
            "summary": summary,
        }

    def get_summary(self) -> Dict[str, Any]:
        summary = self._engine.get_summary()
        summary["target_url"] = self.target_url
        summary["attack_breakdown"] = self._monitor.rate_tracker.get_breakdown()
        if self._start_time:
            summary["analysis_time_ms"] = round(
                (time.time() - self._start_time) * 1000, 1
            )
        return summary

    def get_battle_log(self) -> List[str]:
        return list(self._battle_log)

    def reset(self) -> None:
        self._monitor.reset()
        self._engine.reset()
        self._results.clear()
        self._battle_log.clear()
        self._start_time = None
