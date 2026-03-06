"""
event_bus.py — Lightweight attack/defense event system
------------------------------------------------------
Thread-safe publish/subscribe event bus that allows AttackBot results
to be broadcast to DefendBot listeners in real time.

Does NOT modify any existing attack or defense logic.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Event types ───────────────────────────────────────────────────────────

class AttackEvent:
    """Immutable event emitted when an attack module produces results."""

    __slots__ = (
        "attack_type", "target_url", "findings_dicts", "scan_log",
        "summary", "raw_result",
    )

    def __init__(
        self,
        attack_type: str,
        target_url: str = "",
        findings_dicts: Optional[List[Dict[str, Any]]] = None,
        scan_log: Optional[list] = None,
        summary: Optional[Dict[str, Any]] = None,
        raw_result: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.attack_type = attack_type
        self.target_url = target_url
        self.findings_dicts = findings_dicts or []
        self.scan_log = scan_log
        self.summary = summary or {}
        self.raw_result = raw_result or {}


# ── Listener callback type ────────────────────────────────────────────────

AttackListener = Callable[[AttackEvent], None]


# ── Event bus ─────────────────────────────────────────────────────────────

class EventBus:
    """
    Thread-safe pub/sub bus for attack → defense communication.

    Usage::

        bus = EventBus()
        bus.subscribe("SQL_INJECTION", my_sql_handler)
        bus.publish(AttackEvent(attack_type="SQL_INJECTION", ...))
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._listeners: Dict[str, List[AttackListener]] = {}
        self._global_listeners: List[AttackListener] = []
        self._event_log: List[Dict[str, Any]] = []

    # ── subscription ──────────────────────────────────────────────────

    def subscribe(self, attack_type: str, callback: AttackListener) -> None:
        """Register *callback* to be invoked for events of *attack_type*."""
        with self._lock:
            self._listeners.setdefault(attack_type, []).append(callback)

    def subscribe_all(self, callback: AttackListener) -> None:
        """Register *callback* for every event regardless of type."""
        with self._lock:
            self._global_listeners.append(callback)

    # ── publishing ────────────────────────────────────────────────────

    def publish(self, event: AttackEvent) -> None:
        """
        Broadcast *event* to all registered listeners.

        Listeners are invoked synchronously in the calling thread so that
        defense results are available immediately after the attack task
        finishes.
        """
        with self._lock:
            targets = list(self._listeners.get(event.attack_type, []))
            targets += list(self._global_listeners)

        self._event_log.append({
            "attack_type": event.attack_type,
            "findings_count": len(event.findings_dicts),
            "has_scan_log": event.scan_log is not None,
        })

        for cb in targets:
            try:
                cb(event)
            except Exception as exc:
                logger.warning(
                    "[EventBus] Listener error for %s: %s",
                    event.attack_type, exc,
                )

    # ── introspection ─────────────────────────────────────────────────

    @property
    def event_log(self) -> List[Dict[str, Any]]:
        return list(self._event_log)

    def reset(self) -> None:
        with self._lock:
            self._listeners.clear()
            self._global_listeners.clear()
            self._event_log.clear()
