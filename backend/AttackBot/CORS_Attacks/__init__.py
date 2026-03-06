# CORS_Attacks sub-package
# Re-exports key symbols for use via AttackBot.CORS_Attacks.*

from .cors_payloads import (
    CORSOriginPayload,
    ALL_CORS_ORIGINS,
    MALICIOUS_ORIGINS,
    NULL_ORIGINS,
    LOCALHOST_ORIGINS,
    SUBDOMAIN_ORIGINS,
    PROTOCOL_ORIGINS,
)
from .cors_attack_bot import CORSAttackBot, CORSFinding, CORSScanConfig, CORSIssueType

__all__ = [
    "CORSAttackBot",
    "CORSFinding",
    "CORSScanConfig",
    "CORSIssueType",
    "CORSOriginPayload",
    "ALL_CORS_ORIGINS",
]
