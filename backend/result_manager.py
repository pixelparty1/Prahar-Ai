"""
result_manager.py — Thread-Safe Result Collection
---------------------------------------------------
Provides atomic, non-blocking result recording for parallel scan workers.

Improvements addressed:
  3 — Atomic result recording (thread-safe via Lock)
  5 — Result normalization (dedup by endpoint+type+parameter)
  7 — Non-blocking result pipeline (workers push, collector aggregates)

Does NOT modify any attack detection logic.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional, Tuple


class ResultCollector:
    """
    Thread-safe collector that accumulates findings from parallel workers.

    Workers call ``add()`` or ``add_many()`` from any thread; results are
    guarded by a lock so no writes are lost or duplicated by race conditions.

    An optional *normalizer* function extracts a dedup key from each finding.
    When set, identical findings (by key) are recorded only once.
    """

    def __init__(
        self,
        normalizer: Optional[Callable[[Any], Optional[Tuple]]] = None,
    ):
        self._lock = threading.Lock()
        self._items: List[Any] = []
        self._seen_keys: set = set()
        self._normalizer = normalizer

    # ── Write API (called by workers) ─────────────────────────────────

    def add(self, item: Any) -> bool:
        """
        Atomically add a single finding.
        Returns True if it was actually added (not a duplicate).
        """
        with self._lock:
            if self._normalizer is not None:
                key = self._normalizer(item)
                if key is not None and key in self._seen_keys:
                    return False
                if key is not None:
                    self._seen_keys.add(key)
            self._items.append(item)
            return True

    def add_many(self, items: List[Any]) -> int:
        """
        Atomically add multiple findings.
        Returns the count of items actually added (after dedup).
        """
        added = 0
        with self._lock:
            for item in items:
                if self._normalizer is not None:
                    key = self._normalizer(item)
                    if key is not None and key in self._seen_keys:
                        continue
                    if key is not None:
                        self._seen_keys.add(key)
                self._items.append(item)
                added += 1
        return added

    # ── Read API ──────────────────────────────────────────────────────

    def get_all(self) -> List[Any]:
        """Return a snapshot of all collected items."""
        with self._lock:
            return list(self._items)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._seen_keys.clear()


# ── Pre-built normalizer functions ────────────────────────────────────────

def sqli_normalizer(result: Any) -> Optional[Tuple]:
    """Dedup key for SQL injection AnalysisResult objects."""
    try:
        return (
            getattr(result, "endpoint", ""),
            getattr(result, "parameter", ""),
            tuple(sorted(t.value for t in getattr(result, "injection_types", []))),
        )
    except Exception:
        return None


def xss_normalizer(finding: Any) -> Optional[Tuple]:
    """Dedup key for XSSFinding objects."""
    try:
        return (
            getattr(finding, "endpoint", ""),
            getattr(finding, "parameter", ""),
            str(getattr(finding, "xss_type", "")),
        )
    except Exception:
        return None


def xss_dict_normalizer(finding: Dict) -> Optional[Tuple]:
    """Dedup key for XSS finding dicts."""
    try:
        return (
            finding.get("endpoint", ""),
            finding.get("parameter", ""),
            finding.get("xss_type", ""),
        )
    except Exception:
        return None


def cors_normalizer(finding: Any) -> Optional[Tuple]:
    """Dedup key for CORSFinding objects."""
    try:
        return (
            getattr(finding, "endpoint", ""),
            str(getattr(finding, "issue_type", "")),
            getattr(finding, "origin_sent", ""),
        )
    except Exception:
        return None


def cors_dict_normalizer(finding: Dict) -> Optional[Tuple]:
    """Dedup key for CORS finding dicts."""
    try:
        return (
            finding.get("endpoint", ""),
            finding.get("issue_type", ""),
            finding.get("origin_sent", ""),
        )
    except Exception:
        return None
