"""
sql_defense_bot.py
------------------
Main SQL Injection DefendBot orchestrator.

Ties together the defense monitor, defense engine, and defense rules
to simulate a complete defensive response to SQL injection attacks.

The DefendBot runs **simultaneously** with the AttackBot by:
  1. Receiving the AttackBot's scan_log after each scan chunk completes.
  2. Processing every attack event through the defense engine.
  3. Generating a structured defense report alongside the attack report.

The DefendBot does NOT modify any AttackBot code or behavior.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from .defense_monitor import AttackEvent, DefenseMonitor
from .defense_response import DefenseEngine
from .defense_rules import (
    ALL_DEFENSE_RULES,
    DefenseAction,
    DefenseRule,
    DefenseTechnique,
    DefenseVerdict,
)

logger = logging.getLogger(__name__)


class SQLDefenseBot:
    """
    SQL Injection DefendBot — monitors and responds to AttackBot payloads.

    Usage
    -----
    >>> defend_bot = SQLDefenseBot(target_url="http://127.0.0.1:9000")
    >>> # After AttackBot completes a scan chunk:
    >>> defend_bot.analyze_scan_log(bot.scan_log)
    >>> # Get defense results:
    >>> results = defend_bot.get_results()
    """

    def __init__(
        self,
        target_url: str = "",
        rules: Optional[List[DefenseRule]] = None,
        rate_window: float = 10.0,
        rate_threshold: int = 15,
    ):
        self.target_url = target_url.rstrip("/")

        self._monitor = DefenseMonitor(
            rate_window=rate_window,
            rate_threshold=rate_threshold,
        )
        self._engine = DefenseEngine(rules=rules)

        # Register the defense engine as a handler on the monitor
        self._monitor.register_handler(self._on_attack_event)

        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

    # ── Core: analyze scan log ────────────────────────────────────────

    def analyze_scan_log(self, scan_log: list) -> List[DefenseVerdict]:
        """
        Process an AttackBot scan_log and generate defense verdicts.

        This is the main entry point called after the AttackBot finishes
        scanning (or after each parallel chunk completes).

        Parameters
        ----------
        scan_log : list
            List of ScanLogEntry objects from the AttackBot.

        Returns
        -------
        list[DefenseVerdict]
            One verdict per attack event.
        """
        if self._start_time is None:
            self._start_time = time.time()

        events = self._monitor.process_scan_log(scan_log)
        self._end_time = time.time()

        verdicts = self._engine.verdicts[-len(events):]  # latest batch

        blocked = sum(1 for v in verdicts if v.blocked)
        total = len(verdicts)
        logger.info(
            "[SQLDefenseBot] Analyzed %d attack(s) — %d blocked, %d allowed",
            total, blocked, total - blocked,
        )

        return verdicts

    # ── Event handler (called by monitor for each attack) ─────────────

    def _on_attack_event(self, event: AttackEvent, rate_exceeded: bool) -> None:
        """
        Defense callback invoked for each attack event.
        
        This simulates real-time defense: the DefendBot evaluates the
        attack and produces a verdict immediately.
        """
        verdict = self._engine.evaluate(event, rate_exceeded=rate_exceeded)

        if verdict.blocked and logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "[SQLDefenseBot] BLOCKED: %s → %s | %s | %s",
                verdict.endpoint,
                verdict.technique.value if verdict.technique else "N/A",
                verdict.category,
                verdict.payload[:50],
            )

    # ── Results accessors ─────────────────────────────────────────────

    def get_results(self) -> Dict[str, Any]:
        """
        Return the complete defense results.

        Returns
        -------
        dict
            ``{success, target_url, verdicts, summary, duration_seconds}``
        """
        summary = self._engine.get_summary()
        duration = (
            (self._end_time - self._start_time)
            if self._start_time and self._end_time
            else 0.0
        )

        return {
            "success": True,
            "target_url": self.target_url,
            "verdicts": self._engine.get_verdicts_as_dicts(),
            "summary": summary,
            "duration_seconds": round(duration, 2),
            "total_events_processed": self._monitor.events_processed,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Return just the defense summary statistics."""
        return self._engine.get_summary()

    def get_verdicts(self) -> List[DefenseVerdict]:
        """Return all defense verdicts."""
        return self._engine.verdicts

    def get_verdicts_as_dicts(self) -> List[Dict[str, Any]]:
        """Return all verdicts as plain dicts for JSON serialization."""
        return self._engine.get_verdicts_as_dicts()

    def get_battle_log(self) -> List[Dict[str, Any]]:
        """
        Return an attack-vs-defense battle log showing each engagement.

        Each entry pairs an attack with its defense response, suitable
        for display as a real-time cyber battle narrative.
        """
        battle: List[Dict[str, Any]] = []
        for verdict in self._engine.verdicts:
            entry = {
                "attack": {
                    "type": "SQL Injection",
                    "category": verdict.category,
                    "endpoint": verdict.endpoint,
                    "parameter": verdict.parameter,
                    "payload": verdict.payload,
                },
                "defense": {
                    "action": verdict.action.value,
                    "technique": verdict.technique.value if verdict.technique else "None",
                    "explanation": verdict.explanation,
                    "rules_triggered": [r.name for r in verdict.triggered_rules],
                    "safe_query_example": verdict.safe_query_example,
                },
                "result": "Attack Mitigated" if verdict.blocked else "Attack Allowed",
            }
            battle.append(entry)
        return battle

    # ── Reset ─────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Reset all state for a new scan."""
        self._engine.reset()
        self._monitor.reset()
        self._start_time = None
        self._end_time = None

    # ── String representation ─────────────────────────────────────────

    def __repr__(self) -> str:
        summary = self._engine.get_summary()
        return (
            f"SQLDefenseBot(target={self.target_url!r}, "
            f"analyzed={summary['total_attacks_analyzed']}, "
            f"blocked={summary['attacks_blocked']}, "
            f"defense_rate={summary['defense_rate']}%)"
        )
