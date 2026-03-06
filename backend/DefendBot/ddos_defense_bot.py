"""
ddos_defense_bot.py
-------------------
Top-level façade that wires together the DDoS defense monitor, rules,
and response engine.

Usage:
    bot = DDoSDefenseBot(target_url="https://example.com")
    results = bot.analyze_findings(findings_dicts)
    print(bot.get_summary())
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .ddos_defense_monitor import DDoSDefenseMonitor
from .ddos_defense_response import DDoSDefenseEngine
from .ddos_defense_rules import ALL_DDOS_DEFENSE_RULES, DDoSDefenseRule


class DDoSDefenseBot:
    """
    Analyses DDoS findings produced by the DDoSAttackBot and simulates
    realistic infrastructure-level defences against each finding.
    """

    def __init__(
        self,
        target_url: str = "",
        rules: Optional[List[DDoSDefenseRule]] = None,
    ) -> None:
        self.target_url = target_url
        self._monitor = DDoSDefenseMonitor()
        self._engine = DDoSDefenseEngine(rules or list(ALL_DDOS_DEFENSE_RULES))
        self._verdict_dicts: List[Dict[str, Any]] = []
        self._battle_log: List[str] = []
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

    # ── public API ────────────────────────────────────────────────────

    def analyze_findings(
        self,
        findings_dicts: List[Dict[str, Any]],
        as_dicts: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Process a list of finding dicts from DDoSRunner.

        Returns a list of verdict dicts (if *as_dicts* is True) or
        DDoSDefenseVerdict objects.
        """
        self._start_time = time.time()
        events = self._monitor.process_findings(findings_dicts)

        results = []
        for evt in events:
            verdict = self._engine.evaluate(evt)
            entry = verdict.to_dict() if as_dicts else verdict
            results.append(entry)
            self._verdict_dicts.append(verdict.to_dict())

            # Build battle log entry
            status = "MITIGATED" if verdict.mitigated else "ALLOWED"
            self._battle_log.append(
                f"[{status}] {evt.attack_type} @ {evt.endpoint} "
                f"→ {verdict.action.value}"
                f"{(' via ' + verdict.technique.value) if verdict.technique else ''}"
            )

        self._end_time = time.time()
        return results

    def get_results(self) -> Dict[str, Any]:
        """Return complete defense results (summary + verdicts)."""
        summary = self._engine.get_summary()
        summary["target_url"] = self.target_url
        summary["attack_breakdown"] = self._monitor.rate_tracker.get_breakdown()
        if self._start_time and self._end_time:
            summary["analysis_time_ms"] = round(
                (self._end_time - self._start_time) * 1000, 1
            )
        return {
            "success": True,
            "target_url": self.target_url,
            "verdicts": list(self._verdict_dicts),
            "summary": summary,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Return just the summary dict."""
        summary = self._engine.get_summary()
        summary["target_url"] = self.target_url
        summary["attack_breakdown"] = self._monitor.rate_tracker.get_breakdown()
        if self._start_time and self._end_time:
            summary["analysis_time_ms"] = round(
                (self._end_time - self._start_time) * 1000, 1
            )
        return summary

    def get_battle_log(self) -> List[str]:
        return list(self._battle_log)

    def reset(self) -> None:
        self._monitor.reset()
        self._engine.reset()
        self._verdict_dicts.clear()
        self._battle_log.clear()
        self._start_time = None
        self._end_time = None
