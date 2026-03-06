"""
cors_defense_monitor.py
-----------------------
Event monitor that observes CORS attack findings from the CORSAttackBot
and converts them into normalized defense events.

The monitor does NOT modify AttackBot behavior — it only reads the
findings produced by CORSAttackBot/CORSRunner and generates defense
events for each attack finding.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── CORS Attack Event ─────────────────────────────────────────────────────

@dataclass
class CORSAttackEvent:
    """
    Normalized CORS attack event extracted from a CORSFinding dict.

    Fields mirror the CORSFinding.to_dict() structure so the defense
    engine can operate without importing AttackBot code.
    """
    endpoint: str
    method: str
    origin_sent: str
    issue_type: str
    severity: str
    acao_header: str          # Access-Control-Allow-Origin
    acac_header: str          # Access-Control-Allow-Credentials
    acam_header: str          # Access-Control-Allow-Methods
    acah_header: str          # Access-Control-Allow-Headers
    content_type: str
    impact: str
    confidence: str

    @classmethod
    def from_finding_dict(cls, finding: Dict[str, Any]) -> "CORSAttackEvent":
        """Create from a CORSFinding.to_dict() result (duck-typed)."""
        headers = finding.get("response_headers", {})
        return cls(
            endpoint=finding.get("endpoint", ""),
            method=finding.get("method", "GET"),
            origin_sent=finding.get("origin_sent", ""),
            issue_type=finding.get("issue_type", ""),
            severity=finding.get("severity", ""),
            acao_header=headers.get("Access-Control-Allow-Origin", ""),
            acac_header=headers.get("Access-Control-Allow-Credentials", ""),
            acam_header=headers.get("Access-Control-Allow-Methods", ""),
            acah_header=headers.get("Access-Control-Allow-Headers", ""),
            content_type=headers.get("Content-Type", ""),
            impact=finding.get("impact", ""),
            confidence=finding.get("confidence", ""),
        )

    @classmethod
    def from_finding_object(cls, finding) -> "CORSAttackEvent":
        """Create from a CORSFinding object (duck-typed via getattr)."""
        return cls(
            endpoint=getattr(finding, "endpoint", ""),
            method=getattr(finding, "method", "GET"),
            origin_sent=getattr(finding, "origin_sent", ""),
            issue_type=getattr(finding, "issue_type", ""),
            severity=getattr(finding, "severity", ""),
            acao_header=getattr(finding, "acao_header", ""),
            acac_header=getattr(finding, "acac_header", ""),
            acam_header=getattr(finding, "acam_header", ""),
            acah_header=getattr(finding, "acah_header", ""),
            content_type=getattr(finding, "content_type", ""),
            impact=getattr(finding, "impact", ""),
            confidence=getattr(finding, "confidence", ""),
        )


# ── Endpoint Rate Tracker ────────────────────────────────────────────────

class CORSRateTracker:
    """
    Track CORS attack rates per endpoint.

    Thread-safe. Counts how many distinct attack types target each endpoint.
    """

    def __init__(self, threshold: int = 5):
        self._threshold = threshold
        self._counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def record(self, endpoint: str) -> bool:
        """
        Record an attack on an endpoint.
        Returns True if the endpoint is being heavily targeted.
        """
        with self._lock:
            self._counts[endpoint] += 1
            return self._counts[endpoint] > self._threshold

    def get_count(self, endpoint: str) -> int:
        with self._lock:
            return self._counts.get(endpoint, 0)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


# ── CORS Defense Monitor ─────────────────────────────────────────────────

class CORSDefenseMonitor:
    """
    Observes CORS attack events and forwards them to registered handlers.

    Bridges the CORSAttackBot findings and the CORS defense engine.
    Converts CORSFinding dicts into CORSAttackEvent objects and invokes
    the defense callback for each one.
    """

    def __init__(self, rate_threshold: int = 5):
        self._handlers: List[Callable[[CORSAttackEvent, bool], Any]] = []
        self.rate_tracker = CORSRateTracker(threshold=rate_threshold)
        self._events_processed: int = 0
        self._lock = threading.Lock()

    def register_handler(
        self, handler: Callable[[CORSAttackEvent, bool], Any]
    ) -> None:
        """Register a callback invoked for each CORS attack event."""
        self._handlers.append(handler)

    def process_findings(
        self, findings: list, as_dicts: bool = True
    ) -> List[CORSAttackEvent]:
        """
        Process a list of CORS findings and invoke handlers for each.

        Parameters
        ----------
        findings : list
            Either a list of CORSFinding.to_dict() dicts (as_dicts=True)
            or a list of CORSFinding objects (as_dicts=False).
        as_dicts : bool
            If True, treat each item as a dict. If False, as an object.

        Returns
        -------
        list[CORSAttackEvent]
        """
        events: List[CORSAttackEvent] = []
        for finding in findings:
            if as_dicts:
                event = CORSAttackEvent.from_finding_dict(finding)
            else:
                event = CORSAttackEvent.from_finding_object(finding)

            heavily_targeted = self.rate_tracker.record(event.endpoint)

            for handler in self._handlers:
                try:
                    handler(event, heavily_targeted)
                except Exception as exc:
                    logger.debug("[CORSDefenseMonitor] Handler error: %s", exc)

            events.append(event)
            with self._lock:
                self._events_processed += 1

        return events

    @property
    def events_processed(self) -> int:
        with self._lock:
            return self._events_processed

    def reset(self) -> None:
        with self._lock:
            self._events_processed = 0
        self.rate_tracker.reset()
