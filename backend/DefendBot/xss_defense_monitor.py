"""
xss_defense_monitor.py
----------------------
Monitors and normalises XSS attack findings from the XSSAttackBot,
converting raw finding dicts into typed XSSAttackEvent objects for the
defense engine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class XSSAttackEvent:
    """
    Normalised representation of a single XSS attack finding.
    Created from the dict produced by ``XSSFinding.to_dict()``.
    """
    endpoint: str
    parameter: str
    method: str
    payload: str
    xss_type: str
    severity: str
    evidence: str = ""
    confidence: str = ""
    source_file: str = ""
    source_line: int = 0
    response_snippet: str = ""
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_finding_dict(cls, d: Dict[str, Any]) -> "XSSAttackEvent":
        return cls(
            endpoint=d.get("endpoint", ""),
            parameter=d.get("parameter", ""),
            method=d.get("method", ""),
            payload=d.get("payload", ""),
            xss_type=d.get("xss_type", "Unknown"),
            severity=d.get("severity", "HIGH"),
            evidence=d.get("evidence", ""),
            confidence=d.get("confidence", ""),
            source_file=d.get("source_file", ""),
            source_line=d.get("source_line", 0),
            response_snippet=d.get("response_snippet", ""),
        )


class XSSRateTracker:
    """
    Simple sliding-window counter tracking attack rate by XSS type.
    """

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}
        self._total: int = 0

    def record(self, xss_type: str) -> None:
        self._counts[xss_type] = self._counts.get(xss_type, 0) + 1
        self._total += 1

    @property
    def total(self) -> int:
        return self._total

    def get_count(self, xss_type: str) -> int:
        return self._counts.get(xss_type, 0)

    def get_breakdown(self) -> Dict[str, int]:
        return dict(self._counts)


class XSSDefenseMonitor:
    """
    Ingests raw XSS finding dicts and exposes typed events.
    """

    def __init__(self) -> None:
        self._events: List[XSSAttackEvent] = []
        self._rate_tracker = XSSRateTracker()

    def process_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[XSSAttackEvent]:
        events: List[XSSAttackEvent] = []
        for f in findings:
            evt = XSSAttackEvent.from_finding_dict(f)
            self._events.append(evt)
            self._rate_tracker.record(evt.xss_type)
            events.append(evt)
        return events

    @property
    def events(self) -> List[XSSAttackEvent]:
        return list(self._events)

    @property
    def rate_tracker(self) -> XSSRateTracker:
        return self._rate_tracker

    def reset(self) -> None:
        self._events.clear()
        self._rate_tracker = XSSRateTracker()
