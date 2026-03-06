"""
defense_monitor.py
------------------
Event monitor that observes SQL injection attack events from the
AttackBot's scan log and forwards them to the defense engine.

The monitor does NOT modify AttackBot behavior — it only reads
the scan_log entries produced by SQLInjectionAttackBot and
generates defense events for each attack attempt.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Attack Event ──────────────────────────────────────────────────────────

@dataclass
class AttackEvent:
    """
    Normalized attack event extracted from a ScanLogEntry.

    Fields mirror the ScanLogEntry structure so the defense engine can
    operate without importing AttackBot code.
    """
    timestamp: float
    endpoint: str
    parameter: str
    payload: str
    category: str
    status_code: int
    response_time: float
    vulnerable: bool

    @classmethod
    def from_scan_log_entry(cls, entry) -> "AttackEvent":
        """Create from a ScanLogEntry (duck-typed — no direct import)."""
        return cls(
            timestamp=getattr(entry, "timestamp", 0.0),
            endpoint=getattr(entry, "endpoint", ""),
            parameter=getattr(entry, "parameter", ""),
            payload=getattr(entry, "payload", ""),
            category=getattr(entry, "category", ""),
            status_code=getattr(entry, "status_code", 0),
            response_time=getattr(entry, "response_time", 0.0),
            vulnerable=getattr(entry, "vulnerable", False),
        )


# ── Rate Tracker ──────────────────────────────────────────────────────────

class RateTracker:
    """
    Track request rates per endpoint to detect rapid-fire attack patterns.

    Thread-safe via a lock so it can be used from concurrent scan workers.
    """

    def __init__(self, window_seconds: float = 10.0, threshold: int = 15):
        self._window = window_seconds
        self._threshold = threshold
        self._timestamps: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record(self, endpoint: str, ts: float) -> bool:
        """
        Record an attack attempt timestamp.

        Returns True if the rate limit is exceeded.
        """
        with self._lock:
            bucket = self._timestamps[endpoint]
            cutoff = ts - self._window
            # Prune old entries
            self._timestamps[endpoint] = [t for t in bucket if t > cutoff]
            self._timestamps[endpoint].append(ts)
            return len(self._timestamps[endpoint]) > self._threshold

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def window(self) -> float:
        return self._window

    def get_count(self, endpoint: str) -> int:
        """Return current request count for an endpoint."""
        with self._lock:
            return len(self._timestamps.get(endpoint, []))

    def reset(self) -> None:
        with self._lock:
            self._timestamps.clear()


# ── Defense Event Monitor ─────────────────────────────────────────────────

class DefenseMonitor:
    """
    Observes attack events and forwards them to registered defense handlers.

    This is the bridge between the AttackBot's scan log and the DefendBot's
    defense engine. It converts ScanLogEntry objects into AttackEvent
    objects and invokes the defense callback for each one.
    """

    def __init__(self, rate_window: float = 10.0, rate_threshold: int = 15):
        self._handlers: List[Callable[[AttackEvent, bool], Any]] = []
        self.rate_tracker = RateTracker(
            window_seconds=rate_window,
            threshold=rate_threshold,
        )
        self._events_processed: int = 0
        self._lock = threading.Lock()

    def register_handler(self, handler: Callable[[AttackEvent, bool], Any]) -> None:
        """Register a callback invoked for each attack event.

        The callback receives ``(event: AttackEvent, rate_exceeded: bool)``.
        """
        self._handlers.append(handler)

    def process_scan_log(self, scan_log: list) -> List[AttackEvent]:
        """
        Process a complete scan log (list of ScanLogEntry) and invoke
        handlers for each entry.

        Called after the AttackBot finishes scanning a chunk.

        Returns the list of AttackEvent objects generated.
        """
        events: List[AttackEvent] = []
        for entry in scan_log:
            event = AttackEvent.from_scan_log_entry(entry)
            rate_exceeded = self.rate_tracker.record(event.endpoint, event.timestamp)

            for handler in self._handlers:
                try:
                    handler(event, rate_exceeded)
                except Exception as exc:
                    logger.debug("[DefenseMonitor] Handler error: %s", exc)

            events.append(event)
            with self._lock:
                self._events_processed += 1

        return events

    @property
    def events_processed(self) -> int:
        with self._lock:
            return self._events_processed

    def reset(self) -> None:
        """Reset internal state for a new scan."""
        with self._lock:
            self._events_processed = 0
        self.rate_tracker.reset()
