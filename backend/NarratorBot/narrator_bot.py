"""
narrator_bot.py — Live commentator for Prahaar AI simulations
--------------------------------------------------------------
The NarratorBot observes attack and defense events in real time and
produces human-readable commentary describing the simulation.

It functions like a **live sports commentator** for cybersecurity —
explaining what AttackBot and DefendBot are doing, turn by turn.

CRITICAL: The NarratorBot is strictly read-only.  It NEVER modifies
events, attack logic, defense logic, or the orchestrator.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .narrator_formatter import NarratorFormatter
from .narrator_listener import NarratorListener

logger = logging.getLogger(__name__)

# ── Prefix used on every narration line ──────────────────────────────

_PREFIX = "[NARRATOR]"


class NarratorBot:
    """
    Live commentary bot for Prahaar AI attack-defense simulations.

    Usage (with orchestrator)::

        from orchestrator.event_bus import EventBus
        from NarratorBot import NarratorBot

        bus = EventBus()
        narrator = NarratorBot()
        narrator.attach(bus)

        # ... orchestrator publishes events on the bus ...
        # Narrator automatically prints commentary.

        # After simulation finishes, retrieve the full transcript:
        transcript = narrator.get_transcript()

    Usage (standalone — from defense results)::

        narrator = NarratorBot()
        narrator.narrate_defense("SQL_INJECTION", defense_summary, battle_log)
    """

    def __init__(
        self,
        verbose: bool = True,
        output_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Parameters
        ----------
        verbose : bool
            If True (default), prints narration to stdout in real time.
        output_callback : callable, optional
            If provided, each narration line is also passed to this
            callback (e.g. for WebSocket broadcasting).
        """
        self._formatter = NarratorFormatter()
        self._listener = NarratorListener()
        self._verbose = verbose
        self._output_callback = output_callback

        self._lock = threading.Lock()
        self._transcript: List[str] = []
        self._defense_transcript: List[str] = []
        self._start_time: Optional[float] = None

        # Register ourselves as the listener callback
        self._listener.on_event(self._on_event)

    # ── EventBus integration ──────────────────────────────────────────

    def attach(self, bus: Any) -> None:
        """
        Subscribe to all events on the given EventBus.

        This must be called **before** the orchestrator publishes events.
        """
        self._start_time = time.time()
        self._listener.attach(bus)
        self._emit(f"\n{'━' * 60}")
        self._emit(f"  {_PREFIX}  PRAHAAR AI — LIVE BATTLE NARRATION")
        self._emit(f"{'━' * 60}")
        self._emit("  NarratorBot is online. Awaiting attack events...\n")

    # ── Event callback (called by listener for each event) ────────────

    def _on_event(self, event: Any) -> None:
        """Process an AttackEvent and produce commentary."""
        lines = self._formatter.narrate_attack_event(
            attack_type=event.attack_type,
            target_url=event.target_url,
            findings_dicts=event.findings_dicts,
            scan_log=event.scan_log,
            summary=event.summary,
        )

        self._emit("")
        self._emit(f"{'─' * 60}")
        self._emit(f"  {_PREFIX}  ATTACK EVENT — {event.attack_type}")
        self._emit(f"{'─' * 60}")
        for line in lines:
            self._emit(f"  {line}")

    # ── Manual defense narration (for Mode 2 / standalone) ────────────

    def narrate_defense(
        self,
        attack_type: str,
        defense_summary: Dict[str, Any],
        battle_log: list,
    ) -> List[str]:
        """
        Generate and emit defense commentary.

        Call this after a DefendBot finishes its analysis.
        Returns the list of narration lines produced.
        """
        lines = self._formatter.narrate_defense_summary(
            attack_type=attack_type,
            defense_summary=defense_summary,
            battle_log=battle_log,
        )

        self._emit("")
        self._emit(f"  {_PREFIX}  DEFENSE RESPONSE — {attack_type}")
        for line in lines:
            self._emit(f"  {line}")

        with self._lock:
            self._defense_transcript.extend(lines)

        return lines

    # ── Transcript access ─────────────────────────────────────────────

    def get_transcript(self) -> List[str]:
        """Return the complete narration transcript."""
        with self._lock:
            return list(self._transcript)

    def get_transcript_text(self) -> str:
        """Return the complete narration as a single string."""
        with self._lock:
            return "\n".join(self._transcript)

    def get_defense_transcript(self) -> List[str]:
        """Return only the defense narration portion."""
        with self._lock:
            return list(self._defense_transcript)

    # ── Final summary ─────────────────────────────────────────────────

    def print_final_summary(
        self,
        defense_results: Dict[str, Dict[str, Any]],
        battle_logs: Dict[str, list],
    ) -> None:
        """
        Print a final narration summary after the simulation completes.

        Parameters
        ----------
        defense_results : dict
            Mapping of attack type key (e.g. "sql") to defense result dict.
        battle_logs : dict
            Mapping of attack type key to battle log list.
        """
        elapsed = (time.time() - self._start_time) if self._start_time else 0

        self._emit("")
        self._emit(f"{'━' * 60}")
        self._emit(f"  {_PREFIX}  BATTLE NARRATION SUMMARY")
        self._emit(f"{'━' * 60}")
        self._emit(f"  Simulation duration: {elapsed:.1f}s")
        self._emit("")

        type_map = {
            "sql": "SQL_INJECTION",
            "xss": "XSS",
            "cors": "CORS",
            "ddos": "DDOS",
        }

        for key, attack_type in type_map.items():
            dr = defense_results.get(key)
            bl = battle_logs.get(key, [])

            if dr:
                lines = self._formatter.narrate_defense_summary(
                    attack_type=attack_type,
                    defense_summary=dr.get("summary", {}),
                    battle_log=bl,
                )
                for line in lines:
                    self._emit(f"  {line}")
                self._emit("")
            else:
                label = self._formatter.narrate_attack_event(
                    attack_type, "", [], None, None
                )
                self._emit(f"  {attack_type}: No defense data (attack may have found no vulnerabilities).")
                self._emit("")

        self._emit(f"{'━' * 60}")
        self._emit(f"  {_PREFIX}  END OF NARRATION")
        self._emit(f"{'━' * 60}\n")

    # ── Output helpers ────────────────────────────────────────────────

    def _emit(self, text: str) -> None:
        """Output a narration line to all configured sinks."""
        with self._lock:
            self._transcript.append(text)

        if self._verbose:
            print(text)

        if self._output_callback:
            try:
                self._output_callback(text)
            except Exception:
                pass

    # ── Reset ─────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all transcript state."""
        with self._lock:
            self._transcript.clear()
            self._defense_transcript.clear()
            self._start_time = None
