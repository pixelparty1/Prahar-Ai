"""
ddos_defense_monitor.py
-----------------------
Monitors and normalises DDoS attack findings from the DDoSAttackBot,
converting raw finding dicts into typed DDoSAttackEvent objects for
the defense engine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class DDoSAttackEvent:
    """
    Normalised representation of a single DDoS attack finding.
    Created from the dict produced by ``DDoSFinding.to_dict()``.
    """
    attack_type: str
    severity: str
    endpoint: str
    observation: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    # ── Derived attributes for defense analysis ───────────────────────

    @property
    def request_rate(self) -> float:
        """Requests per second (from details if available)."""
        return float(self.details.get("requests_per_second", 0))

    @property
    def payload_size(self) -> float:
        """Payload size in MB (from details if available)."""
        return float(self.details.get("payload_size_mb", 0))

    @property
    def connection_count(self) -> int:
        """Number of connections (from details if available)."""
        return int(self.details.get("connections", 0))

    @property
    def request_pattern(self) -> str:
        """Request method/pattern observed."""
        return self.details.get("method", "GET")

    @classmethod
    def from_finding_dict(cls, d: Dict[str, Any]) -> "DDoSAttackEvent":
        return cls(
            attack_type=d.get("attack_type", "Unknown"),
            severity=d.get("severity", "HIGH"),
            endpoint=d.get("endpoint", ""),
            observation=d.get("observation", ""),
            recommendation=d.get("recommendation", ""),
            details=d.get("details", {}),
        )


class DDoSRateTracker:
    """Tracks attack frequency by type."""

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}
        self._total: int = 0

    def record(self, attack_type: str) -> None:
        self._counts[attack_type] = self._counts.get(attack_type, 0) + 1
        self._total += 1

    @property
    def total(self) -> int:
        return self._total

    def get_count(self, attack_type: str) -> int:
        return self._counts.get(attack_type, 0)

    def get_breakdown(self) -> Dict[str, int]:
        return dict(self._counts)


class DDoSDefenseMonitor:
    """
    Ingests raw DDoS finding dicts and exposes typed events.
    """

    def __init__(self) -> None:
        self._events: List[DDoSAttackEvent] = []
        self._rate_tracker = DDoSRateTracker()

    def process_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[DDoSAttackEvent]:
        events: List[DDoSAttackEvent] = []
        for f in findings:
            evt = DDoSAttackEvent.from_finding_dict(f)
            self._events.append(evt)
            self._rate_tracker.record(evt.attack_type)
            events.append(evt)
        return events

    @property
    def events(self) -> List[DDoSAttackEvent]:
        return list(self._events)

    @property
    def rate_tracker(self) -> DDoSRateTracker:
        return self._rate_tracker

    @property
    def events_processed(self) -> int:
        return len(self._events)

    def reset(self) -> None:
        self._events.clear()
        self._rate_tracker = DDoSRateTracker()
