"""
defense_response.py
-------------------
Defense engine that evaluates attack payloads against defense rules
and generates defensive verdicts.

This module contains the core logic for:
  • Matching payloads against defense rules
  • Generating parameterized query examples
  • Producing structured defense verdicts
  • Aggregating defense statistics

Does NOT modify any AttackBot code.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from .defense_rules import (
    ALL_DEFENSE_RULES,
    DefenseAction,
    DefenseRule,
    DefenseTechnique,
    DefenseVerdict,
)
from .defense_monitor import AttackEvent

logger = logging.getLogger(__name__)


# ── Parameterized Query Generator ─────────────────────────────────────────

_UNSAFE_QUERY_PATTERNS = [
    (
        re.compile(
            r"SELECT\s+.+?\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*'[^']*'",
            re.IGNORECASE,
        ),
        "SELECT * FROM {table} WHERE {col} = ?",
    ),
    (
        re.compile(
            r"INSERT\s+INTO\s+(\w+)",
            re.IGNORECASE,
        ),
        "INSERT INTO {table} (...) VALUES (?, ?, ?)",
    ),
    (
        re.compile(
            r"UPDATE\s+(\w+)\s+SET",
            re.IGNORECASE,
        ),
        "UPDATE {table} SET col = ? WHERE id = ?",
    ),
    (
        re.compile(
            r"DELETE\s+FROM\s+(\w+)",
            re.IGNORECASE,
        ),
        "DELETE FROM {table} WHERE id = ?",
    ),
]


def _generate_safe_query(payload: str, endpoint: str, parameter: str) -> str:
    """
    Generate a parameterized query example based on the attack payload context.

    Returns a human-readable safe query suggestion.
    """
    for pattern, template in _UNSAFE_QUERY_PATTERNS:
        m = pattern.search(payload)
        if m:
            groups = m.groups()
            table = groups[0] if groups else "table"
            col = groups[1] if len(groups) > 1 else parameter
            return template.format(table=table, col=col)

    # Default: generic parameterized query for the parameter
    return f"SELECT * FROM table WHERE {parameter} = ?"


# ── Defense Response Engine ───────────────────────────────────────────────

class DefenseEngine:
    """
    Evaluates attack payloads against all defense rules and produces
    DefenseVerdict objects.

    Thread-safe — multiple AttackBot worker threads can call evaluate()
    concurrently.
    """

    def __init__(self, rules: Optional[List[DefenseRule]] = None):
        self._rules = rules or list(ALL_DEFENSE_RULES)
        self._verdicts: List[DefenseVerdict] = []
        self._lock = threading.Lock()

        # Statistics
        self._stats = Counter()
        self._per_endpoint: Dict[str, Counter] = defaultdict(Counter)

    def evaluate(
        self,
        event: AttackEvent,
        rate_exceeded: bool = False,
    ) -> DefenseVerdict:
        """
        Evaluate an attack event against all defense rules.

        Parameters
        ----------
        event : AttackEvent
            The attack event to evaluate.
        rate_exceeded : bool
            Whether the rate limiter has flagged this endpoint.

        Returns
        -------
        DefenseVerdict
            The defense action taken.
        """
        verdict = DefenseVerdict(
            payload=event.payload,
            endpoint=event.endpoint,
            parameter=event.parameter,
            category=event.category,
        )

        # Rate limiting check (highest priority override)
        if rate_exceeded:
            verdict.action = DefenseAction.RATE_LIMITED
            verdict.technique = DefenseTechnique.RATE_LIMITING
            verdict.explanation = (
                f"Rate limit exceeded — too many injection attempts on "
                f"{event.endpoint} within the monitoring window."
            )
            verdict.triggered_rules = []
            self._record(verdict)
            return verdict

        # Evaluate payload against all rules (highest priority first)
        matched_rules: List[DefenseRule] = []
        for rule in self._rules:
            if self._matches(rule, event.payload):
                matched_rules.append(rule)

        if matched_rules:
            # Use the highest-priority matching rule as the primary technique
            primary = matched_rules[0]
            verdict.triggered_rules = matched_rules
            verdict.action = primary.action
            verdict.technique = primary.technique
            verdict.explanation = self._build_explanation(primary, event)

            # Generate safe query example for parameterized query rules
            if any(
                r.technique == DefenseTechnique.PARAMETERIZED_QUERY
                for r in matched_rules
            ):
                verdict.safe_query_example = _generate_safe_query(
                    event.payload, event.endpoint, event.parameter,
                )
            # Also provide safe query for any blocked SQL injection
            elif verdict.action == DefenseAction.BLOCKED:
                verdict.safe_query_example = _generate_safe_query(
                    event.payload, event.endpoint, event.parameter,
                )
        else:
            verdict.action = DefenseAction.ALLOWED
            verdict.explanation = "No defense rule triggered — payload appears benign."

        self._record(verdict)
        return verdict

    # ── Rule matching ──────────────────────────────────────────────────

    @staticmethod
    def _matches(rule: DefenseRule, payload: str) -> bool:
        """Check if a payload matches any of the rule's patterns or keywords."""
        for pattern in rule.patterns:
            if pattern.search(payload):
                return True
        payload_upper = payload.upper()
        for keyword in rule.keywords:
            if keyword.upper() in payload_upper:
                return True
        return False

    # ── Explanation generator ──────────────────────────────────────────

    @staticmethod
    def _build_explanation(rule: DefenseRule, event: AttackEvent) -> str:
        """Build a human-readable explanation of the defense action."""
        technique = rule.technique.value
        action = rule.action.value

        explanations = {
            DefenseTechnique.INPUT_VALIDATION: (
                f"Input validation detected suspicious SQL keywords in the "
                f"'{event.parameter}' parameter. Request {action.lower()}."
            ),
            DefenseTechnique.PARAMETERIZED_QUERY: (
                f"Vulnerable query pattern detected. The '{event.parameter}' parameter "
                f"should use parameterized queries instead of string concatenation. "
                f"Attack mitigated by query sanitization."
            ),
            DefenseTechnique.QUERY_PATTERN_DETECTION: (
                f"Known SQL injection pattern detected ({event.category}). "
                f"The payload matches a recognized injection technique. "
                f"Request {action.lower()}."
            ),
            DefenseTechnique.WAF: (
                f"WAF rule triggered — malicious SQL pattern detected in request to "
                f"{event.endpoint}. Request {action.lower()} at the application firewall."
            ),
            DefenseTechnique.PRIVILEGE_PROTECTION: (
                f"Privilege escalation attempt detected — payload attempts to modify "
                f"user roles or administrative privileges. Request {action.lower()}."
            ),
            DefenseTechnique.DATA_MODIFICATION_GUARD: (
                f"Destructive SQL operation detected (DELETE/DROP/INSERT). "
                f"Database permission restrictions enforced. Request {action.lower()}."
            ),
            DefenseTechnique.RATE_LIMITING: (
                f"Rate limit exceeded for {event.endpoint}. "
                f"Further requests throttled."
            ),
        }

        return explanations.get(
            rule.technique,
            f"{technique} — {rule.description}. Request {action.lower()}.",
        )

    # ── Recording ──────────────────────────────────────────────────────

    def _record(self, verdict: DefenseVerdict) -> None:
        """Thread-safe recording of a verdict."""
        with self._lock:
            self._verdicts.append(verdict)
            self._stats[verdict.action.value] += 1
            self._per_endpoint[verdict.endpoint][verdict.action.value] += 1

    # ── Accessors ──────────────────────────────────────────────────────

    @property
    def verdicts(self) -> List[DefenseVerdict]:
        with self._lock:
            return list(self._verdicts)

    def get_verdicts_as_dicts(self) -> List[Dict[str, Any]]:
        """Return all verdicts as plain dicts (for JSON serialization)."""
        with self._lock:
            return [v.to_dict() for v in self._verdicts]

    def get_summary(self) -> Dict[str, Any]:
        """Return a summary of defense actions taken."""
        with self._lock:
            total = len(self._verdicts)
            blocked = self._stats.get(DefenseAction.BLOCKED.value, 0)
            mitigated = self._stats.get(DefenseAction.MITIGATED.value, 0)
            rate_limited = self._stats.get(DefenseAction.RATE_LIMITED.value, 0)
            allowed = self._stats.get(DefenseAction.ALLOWED.value, 0)

            # Count by technique
            by_technique: Counter = Counter()
            for v in self._verdicts:
                if v.technique:
                    by_technique[v.technique.value] += 1

            return {
                "total_attacks_analyzed": total,
                "attacks_blocked": blocked,
                "attacks_mitigated": mitigated,
                "attacks_rate_limited": rate_limited,
                "attacks_allowed": allowed,
                "defense_rate": round(
                    (blocked + mitigated + rate_limited) / total * 100, 1
                ) if total > 0 else 0.0,
                "by_technique": dict(by_technique),
                "by_action": dict(self._stats),
            }

    def reset(self) -> None:
        """Reset all verdicts and statistics."""
        with self._lock:
            self._verdicts.clear()
            self._stats.clear()
            self._per_endpoint.clear()
