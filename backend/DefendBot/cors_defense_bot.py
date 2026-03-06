"""
cors_defense_bot.py
-------------------
Main CORS DefendBot orchestrator.

Ties together the CORS defense monitor, defense engine, and defense rules
to simulate a complete defensive response to CORS misconfiguration attacks.

The DefendBot runs **simultaneously** with the CORSAttackBot by:
  1. Receiving the AttackBot's CORS findings after each scan completes.
  2. Processing every finding through the CORS defense engine.
  3. Generating a structured defense report alongside the attack report.

The DefendBot does NOT modify any AttackBot code or behavior.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from .cors_defense_monitor import CORSAttackEvent, CORSDefenseMonitor
from .cors_defense_response import CORSDefenseEngine
from .cors_defense_rules import (
    ALL_CORS_DEFENSE_RULES,
    CORSDefenseAction,
    CORSDefenseRule,
    CORSDefenseTechnique,
    CORSDefenseVerdict,
)

logger = logging.getLogger(__name__)


class CORSDefenseBot:
    """
    CORS DefendBot — monitors and responds to CORS attack findings.

    Usage
    -----
    >>> defend_bot = CORSDefenseBot(target_url="http://127.0.0.1:9000")
    >>> # After CORSAttackBot/CORSRunner completes:
    >>> defend_bot.analyze_findings(cors_findings_dicts)
    >>> results = defend_bot.get_results()
    """

    def __init__(
        self,
        target_url: str = "",
        rules: Optional[List[CORSDefenseRule]] = None,
        rate_threshold: int = 5,
    ):
        self.target_url = target_url.rstrip("/")

        self._monitor = CORSDefenseMonitor(rate_threshold=rate_threshold)
        self._engine = CORSDefenseEngine(rules=rules)

        # Register the engine handler on the monitor
        self._monitor.register_handler(self._on_attack_event)

        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

    # ── Core: analyze CORS findings ───────────────────────────────────

    def analyze_findings(
        self, findings: list, as_dicts: bool = True
    ) -> List[CORSDefenseVerdict]:
        """
        Process CORS attack findings and generate defense verdicts.

        This is the main entry point called after the CORSAttackBot
        finishes scanning.

        Parameters
        ----------
        findings : list
            List of CORSFinding dicts (from findings_dicts) or
            CORSFinding objects (set as_dicts=False).
        as_dicts : bool
            Whether findings are dicts (True) or objects (False).

        Returns
        -------
        list[CORSDefenseVerdict]
            One verdict per CORS attack finding.
        """
        if self._start_time is None:
            self._start_time = time.time()

        events = self._monitor.process_findings(findings, as_dicts=as_dicts)
        self._end_time = time.time()

        verdicts = self._engine.verdicts[-len(events):]  # latest batch

        blocked = sum(1 for v in verdicts if v.blocked)
        total = len(verdicts)
        logger.info(
            "[CORSDefenseBot] Analyzed %d CORS finding(s) — %d mitigated, %d allowed",
            total, blocked, total - blocked,
        )

        return verdicts

    # ── Event handler (called by monitor for each attack) ─────────────

    def _on_attack_event(
        self, event: CORSAttackEvent, heavily_targeted: bool
    ) -> None:
        """
        Defense callback invoked for each CORS attack event.

        Simulates real-time defense: the DefendBot evaluates the attack
        and produces a verdict immediately.
        """
        verdict = self._engine.evaluate(event, heavily_targeted=heavily_targeted)

        if verdict.blocked and logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "[CORSDefenseBot] %s: %s → %s | %s | origin=%s",
                verdict.action.value,
                verdict.endpoint,
                verdict.technique.value if verdict.technique else "N/A",
                verdict.issue_type,
                verdict.origin_sent[:50],
            )

    # ── Results accessors ─────────────────────────────────────────────

    def get_results(self) -> Dict[str, Any]:
        """
        Return the complete CORS defense results.

        Returns
        -------
        dict
            ``{success, target_url, verdicts, summary, duration_seconds, ...}``
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
        """Return just the CORS defense summary statistics."""
        return self._engine.get_summary()

    def get_verdicts(self) -> List[CORSDefenseVerdict]:
        """Return all CORS defense verdicts."""
        return self._engine.verdicts

    def get_verdicts_as_dicts(self) -> List[Dict[str, Any]]:
        """Return all verdicts as plain dicts for JSON serialization."""
        return self._engine.get_verdicts_as_dicts()

    def get_battle_log(self) -> List[Dict[str, Any]]:
        """
        Return a CORS attack-vs-defense battle log.

        Each entry pairs an attack with its defense response, suitable
        for display as a real-time cyber battle narrative.
        """
        battle: List[Dict[str, Any]] = []
        for verdict in self._engine.verdicts:
            entry = {
                "attack": {
                    "type": "CORS Misconfiguration",
                    "issue_type": verdict.issue_type,
                    "endpoint": verdict.endpoint,
                    "method": verdict.method,
                    "origin_sent": verdict.origin_sent,
                    "response_headers": {
                        "Access-Control-Allow-Origin": verdict.acao_header,
                        "Access-Control-Allow-Credentials": verdict.acac_header,
                        "Access-Control-Allow-Methods": verdict.acam_header,
                        "Access-Control-Allow-Headers": verdict.acah_header,
                    },
                },
                "defense": {
                    "action": verdict.action.value,
                    "technique": (
                        verdict.technique.value if verdict.technique else "None"
                    ),
                    "explanation": verdict.explanation,
                    "rules_triggered": [r.name for r in verdict.triggered_rules],
                    "safe_header_example": verdict.safe_header_example,
                },
                "result": (
                    "Attack Mitigated" if verdict.blocked else "Attack Allowed"
                ),
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
            f"CORSDefenseBot(target={self.target_url!r}, "
            f"analyzed={summary['total_attacks_analyzed']}, "
            f"mitigated={summary['attacks_mitigated']}, "
            f"defense_rate={summary['defense_rate']}%)"
        )
