"""
narrator_listener.py — Event listener for the NarratorBot
----------------------------------------------------------
Subscribes to the EventBus (via subscribe_all) and feeds incoming
AttackEvent objects to the NarratorBot for commentary.

This module is **read-only** — it never modifies events, attack
results, or defense results.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, Callable, Dict, List

if TYPE_CHECKING:
    from orchestrator.event_bus import AttackEvent, EventBus

logger = logging.getLogger(__name__)


class NarratorListener:
    """
    Bridges the EventBus with the NarratorBot.

    Once :meth:`attach` is called the listener receives every event
    published on the bus and forwards it to a narrator callback.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[AttackEvent], None]] = []
        self._event_history: List[Dict[str, Any]] = []

    # ── Registration ──────────────────────────────────────────────────

    def on_event(self, callback: Callable[[AttackEvent], None]) -> None:
        """Register a callback that will be invoked for every event."""
        with self._lock:
            self._callbacks.append(callback)

    def attach(self, bus: EventBus) -> None:
        """Subscribe to *all* events on the given bus."""
        bus.subscribe_all(self._handle_event)
        logger.info("[NarratorListener] Attached to EventBus — listening for all events")

    # ── Internal handler ──────────────────────────────────────────────

    def _handle_event(self, event: AttackEvent) -> None:
        """Called by EventBus for every published event."""
        snapshot = {
            "attack_type": event.attack_type,
            "target_url": event.target_url,
            "findings_count": len(event.findings_dicts),
            "has_scan_log": event.scan_log is not None,
            "summary": dict(event.summary) if event.summary else {},
        }
        with self._lock:
            self._event_history.append(snapshot)

        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as exc:
                logger.warning("[NarratorListener] Callback error: %s", exc)

    # ── Introspection ─────────────────────────────────────────────────

    @property
    def event_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._event_history)
