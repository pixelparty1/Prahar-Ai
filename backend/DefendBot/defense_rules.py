"""
defense_rules.py
----------------
Central repository of SQL injection defense rules.

Each rule represents a real-world defense mechanism and defines:
  • What SQL patterns / keywords to detect
  • The defense technique name
  • The mitigation action to report

These rules do NOT modify any AttackBot logic — they only inspect
payloads and generate defensive verdicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ── Defense Action Enum ───────────────────────────────────────────────────

class DefenseAction(str, Enum):
    """Outcome of a defense rule evaluation."""
    BLOCKED      = "Blocked"
    MITIGATED    = "Mitigated"
    RATE_LIMITED = "Rate Limited"
    ALLOWED      = "Allowed"


# ── Defense Technique Enum ────────────────────────────────────────────────

class DefenseTechnique(str, Enum):
    """Named defense mechanisms simulated by the DefendBot."""
    INPUT_VALIDATION        = "Input Validation"
    PARAMETERIZED_QUERY     = "Parameterized Query Enforcement"
    QUERY_PATTERN_DETECTION = "Query Pattern Detection"
    RATE_LIMITING           = "Rate Limiting"
    WAF                     = "Web Application Firewall"
    PRIVILEGE_PROTECTION    = "Privilege Escalation Protection"
    DATA_MODIFICATION_GUARD = "Data Modification Protection"


# ── Defense Rule Dataclass ────────────────────────────────────────────────

@dataclass
class DefenseRule:
    """A single defense rule with detection patterns and response."""
    name: str
    technique: DefenseTechnique
    description: str
    patterns: List[re.Pattern] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    action: DefenseAction = DefenseAction.BLOCKED
    priority: int = 0  # higher = checked first


@dataclass
class DefenseVerdict:
    """Result of evaluating a payload against all defense rules."""
    payload: str
    endpoint: str
    parameter: str
    category: str
    triggered_rules: List[DefenseRule] = field(default_factory=list)
    action: DefenseAction = DefenseAction.ALLOWED
    technique: Optional[DefenseTechnique] = None
    explanation: str = ""
    safe_query_example: str = ""

    @property
    def blocked(self) -> bool:
        return self.action in (DefenseAction.BLOCKED, DefenseAction.RATE_LIMITED)

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "attack_category": self.category,
            "defense_action": self.action.value,
            "defense_technique": self.technique.value if self.technique else "None",
            "explanation": self.explanation,
            "rules_triggered": [r.name for r in self.triggered_rules],
            "safe_query_example": self.safe_query_example,
            "blocked": self.blocked,
        }


# ══════════════════════════════════════════════════════════════════════════
# DEFENSE RULE DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════

# Flags for case-insensitive matching
_I = re.IGNORECASE

# ── 1. Input Validation Rules ─────────────────────────────────────────────

INPUT_VALIDATION_RULE = DefenseRule(
    name="SQL Keyword Input Validation",
    technique=DefenseTechnique.INPUT_VALIDATION,
    description="Detect suspicious SQL keywords in user input.",
    keywords=[
        "SELECT", "UNION", "DROP", "INSERT", "DELETE", "UPDATE",
        "OR 1=1", "OR '1'='1", "OR 'a'='a", "OR ''='",
    ],
    patterns=[
        re.compile(r"\b(SELECT|UNION|DROP|INSERT|DELETE|UPDATE)\b", _I),
        re.compile(r"\bOR\s+\d+=\d+", _I),
        re.compile(r"\bOR\s+'[^']*'\s*=\s*'[^']*'", _I),
    ],
    action=DefenseAction.BLOCKED,
    priority=10,
)

# ── 2. Parameterized Query Enforcement ────────────────────────────────────

PARAMETERIZED_QUERY_RULE = DefenseRule(
    name="Parameterized Query Enforcement",
    technique=DefenseTechnique.PARAMETERIZED_QUERY,
    description="Detect raw string injection and recommend parameterized queries.",
    patterns=[
        re.compile(r"'\s*(OR|AND)\s+", _I),
        re.compile(r"'\s*;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)", _I),
        re.compile(r"'\s*UNION\s+SELECT", _I),
    ],
    action=DefenseAction.MITIGATED,
    priority=5,
)

# ── 3. Query Pattern Detection ────────────────────────────────────────────

QUERY_PATTERN_RULE = DefenseRule(
    name="Injection Pattern Detection",
    technique=DefenseTechnique.QUERY_PATTERN_DETECTION,
    description="Detect known SQL injection patterns (UNION SELECT, comment injection, stacked queries).",
    patterns=[
        re.compile(r"UNION\s+(ALL\s+)?SELECT", _I),
        re.compile(r"--\s*$", _I),                       # comment injection
        re.compile(r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|WAITFOR)", _I),  # stacked query
        re.compile(r"#\s*$"),                              # MySQL comment
        re.compile(r"/\*.*\*/", _I),                       # block comment
    ],
    action=DefenseAction.BLOCKED,
    priority=8,
)

# ── 4. WAF Rules ─────────────────────────────────────────────────────────

WAF_RULE = DefenseRule(
    name="WAF SQL Injection Filter",
    technique=DefenseTechnique.WAF,
    description="Web Application Firewall rule matching malicious SQL patterns.",
    patterns=[
        re.compile(r"UNION\s+(ALL\s+)?SELECT", _I),
        re.compile(r"INFORMATION_SCHEMA", _I),
        re.compile(r"SLEEP\s*\(", _I),
        re.compile(r"BENCHMARK\s*\(", _I),
        re.compile(r"WAITFOR\s+DELAY", _I),
        re.compile(r"EXTRACTVALUE\s*\(", _I),
        re.compile(r"CONCAT\s*\(", _I),
        re.compile(r"GROUP_CONCAT\s*\(", _I),
        re.compile(r"sqlite_master", _I),
    ],
    action=DefenseAction.BLOCKED,
    priority=15,
)

# ── 5. Privilege Escalation Protection ────────────────────────────────────

PRIVILEGE_PROTECTION_RULE = DefenseRule(
    name="Privilege Escalation Guard",
    technique=DefenseTechnique.PRIVILEGE_PROTECTION,
    description="Block payloads attempting to modify user roles or privileges.",
    patterns=[
        re.compile(r"UPDATE\s+\w+\s+SET\s+\w*(role|admin|privilege|is_admin)", _I),
        re.compile(r"SET\s+role\s*=\s*'admin'", _I),
        re.compile(r"SET\s+is_admin\s*=\s*1", _I),
    ],
    action=DefenseAction.BLOCKED,
    priority=20,
)

# ── 6. Data Modification Protection ──────────────────────────────────────

DATA_MODIFICATION_RULE = DefenseRule(
    name="Data Modification Guard",
    technique=DefenseTechnique.DATA_MODIFICATION_GUARD,
    description="Block payloads attempting destructive operations (DELETE, DROP, INSERT).",
    patterns=[
        re.compile(r"\bDELETE\s+FROM\b", _I),
        re.compile(r"\bDROP\s+TABLE\b", _I),
        re.compile(r"\bDROP\s+TABLE\s+IF\s+EXISTS\b", _I),
        re.compile(r"\bINSERT\s+INTO\b", _I),
        re.compile(r"\bTRUNCATE\s+TABLE\b", _I),
    ],
    action=DefenseAction.BLOCKED,
    priority=20,
)


# ══════════════════════════════════════════════════════════════════════════
# ALL RULES (ordered by priority, highest first)
# ══════════════════════════════════════════════════════════════════════════

ALL_DEFENSE_RULES: List[DefenseRule] = sorted(
    [
        PRIVILEGE_PROTECTION_RULE,
        DATA_MODIFICATION_RULE,
        WAF_RULE,
        INPUT_VALIDATION_RULE,
        QUERY_PATTERN_RULE,
        PARAMETERIZED_QUERY_RULE,
    ],
    key=lambda r: r.priority,
    reverse=True,
)


def get_all_rules() -> List[DefenseRule]:
    """Return all defense rules ordered by priority (highest first)."""
    return list(ALL_DEFENSE_RULES)
