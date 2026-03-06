"""
DefendBot — Security Defense Simulation Module
================================================

Provides real-time defensive analysis of AttackBot scans
for SQL injection and CORS misconfiguration attacks.

Usage::

    from backend.DefendBot import SQLDefenseBot, CORSDefenseBot

    sql_bot = SQLDefenseBot(target_url="http://example.com")
    sql_bot.analyze_scan_log(attacker_scan_log)

    cors_bot = CORSDefenseBot(target_url="http://example.com")
    cors_bot.analyze_findings(cors_findings_dicts)
"""

from .sql_defense_bot import SQLDefenseBot
from .defense_rules import (
    DefenseAction,
    DefenseRule,
    DefenseTechnique,
    DefenseVerdict,
    ALL_DEFENSE_RULES,
)
from .defense_monitor import AttackEvent, DefenseMonitor
from .defense_response import DefenseEngine

from .cors_defense_bot import CORSDefenseBot
from .cors_defense_rules import (
    CORSDefenseAction,
    CORSDefenseRule,
    CORSDefenseTechnique,
    CORSDefenseVerdict,
    ALL_CORS_DEFENSE_RULES,
)
from .cors_defense_monitor import CORSAttackEvent, CORSDefenseMonitor
from .cors_defense_response import CORSDefenseEngine

from .xss_defense_bot import XSSDefenseBot
from .xss_defense_rules import (
    XSSDefenseAction,
    XSSDefenseRule,
    XSSDefenseTechnique,
    XSSDefenseVerdict,
    ALL_XSS_DEFENSE_RULES,
)
from .xss_defense_monitor import XSSAttackEvent, XSSDefenseMonitor
from .xss_defense_response import XSSDefenseEngine

from .ddos_defense_bot import DDoSDefenseBot
from .ddos_defense_rules import (
    DDoSDefenseAction,
    DDoSDefenseRule,
    DDoSDefenseTechnique,
    DDoSDefenseVerdict,
    ALL_DDOS_DEFENSE_RULES,
)
from .ddos_defense_monitor import DDoSAttackEvent, DDoSDefenseMonitor
from .ddos_defense_response import DDoSDefenseEngine

__all__ = [
    # SQL Injection DefendBot
    "SQLDefenseBot",
    "DefenseAction",
    "DefenseRule",
    "DefenseTechnique",
    "DefenseVerdict",
    "ALL_DEFENSE_RULES",
    "AttackEvent",
    "DefenseMonitor",
    "DefenseEngine",
    # CORS DefendBot
    "CORSDefenseBot",
    "CORSDefenseAction",
    "CORSDefenseRule",
    "CORSDefenseTechnique",
    "CORSDefenseVerdict",
    "ALL_CORS_DEFENSE_RULES",
    "CORSAttackEvent",
    "CORSDefenseMonitor",
    "CORSDefenseEngine",
    # XSS DefendBot
    "XSSDefenseBot",
    "XSSDefenseAction",
    "XSSDefenseRule",
    "XSSDefenseTechnique",
    "XSSDefenseVerdict",
    "ALL_XSS_DEFENSE_RULES",
    "XSSAttackEvent",
    "XSSDefenseMonitor",
    "XSSDefenseEngine",
    # DDoS DefendBot
    "DDoSDefenseBot",
    "DDoSDefenseAction",
    "DDoSDefenseRule",
    "DDoSDefenseTechnique",
    "DDoSDefenseVerdict",
    "ALL_DDOS_DEFENSE_RULES",
    "DDoSAttackEvent",
    "DDoSDefenseMonitor",
    "DDoSDefenseEngine",
]
