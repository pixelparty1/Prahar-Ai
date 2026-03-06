"""
cors_defense_rules.py
---------------------
Central repository of CORS defense rules and data structures.

Each rule maps to a real-world CORS security technique and defines
patterns that match against CORS attack findings produced by the
CORSAttackBot.

The DefendBot does NOT modify any AttackBot code — it only reads
the findings produced by the CORS scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Defense action classifications ────────────────────────────────────────

class CORSDefenseAction(str, Enum):
    BLOCKED   = "Blocked"
    HARDENED  = "Hardened"
    ENFORCED  = "Enforced"
    ALLOWED   = "Allowed"


# ── Defense technique enumeration ─────────────────────────────────────────

class CORSDefenseTechnique(str, Enum):
    ORIGIN_VALIDATION       = "Origin Validation"
    CREDENTIAL_PROTECTION   = "Credential Protection"
    NULL_ORIGIN_PROTECTION  = "Null Origin Protection"
    SUBDOMAIN_RESTRICTION   = "Subdomain Trust Restriction"
    PROTOCOL_ENFORCEMENT    = "Protocol Enforcement"
    PREFLIGHT_VALIDATION    = "Preflight Request Validation"
    SENSITIVE_DATA_PROTECTION = "Sensitive Data Protection"
    HEADER_VALIDATION       = "Allowed Header Validation"
    JSON_API_HARDENING      = "JSON API CORS Hardening"


# ── CORS defense rule ────────────────────────────────────────────────────

@dataclass
class CORSDefenseRule:
    """
    A single CORS defense rule that matches attack patterns.

    Attributes
    ----------
    name : str
        Human-readable rule name.
    technique : CORSDefenseTechnique
        Which security technique this rule implements.
    description : str
        What the defense does.
    issue_types : List[str]
        CORSIssueType values this rule handles (from CORSAttackBot).
    action : CORSDefenseAction
        The defensive action taken when the rule fires.
    priority : int
        Higher = evaluated first. Rules are tried in descending priority.
    remediation : str
        Recommended fix for the server administrator.
    """
    name: str
    technique: CORSDefenseTechnique
    description: str
    issue_types: List[str]
    action: CORSDefenseAction
    priority: int = 10
    remediation: str = ""


# ── CORS defense verdict ─────────────────────────────────────────────────

@dataclass
class CORSDefenseVerdict:
    """
    Result of evaluating a CORS attack finding against defense rules.
    """
    endpoint: str
    method: str
    origin_sent: str
    issue_type: str
    severity: str
    triggered_rules: List[CORSDefenseRule] = field(default_factory=list)
    action: CORSDefenseAction = CORSDefenseAction.ALLOWED
    technique: Optional[CORSDefenseTechnique] = None
    explanation: str = ""
    safe_header_example: str = ""
    acao_header: str = ""
    acac_header: str = ""
    acam_header: str = ""
    acah_header: str = ""

    @property
    def blocked(self) -> bool:
        return self.action in (
            CORSDefenseAction.BLOCKED,
            CORSDefenseAction.HARDENED,
            CORSDefenseAction.ENFORCED,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "origin_sent": self.origin_sent,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "action": self.action.value,
            "technique": self.technique.value if self.technique else None,
            "explanation": self.explanation,
            "safe_header_example": self.safe_header_example,
            "triggered_rules": [r.name for r in self.triggered_rules],
            "response_headers": {
                "Access-Control-Allow-Origin": self.acao_header,
                "Access-Control-Allow-Credentials": self.acac_header,
                "Access-Control-Allow-Methods": self.acam_header,
                "Access-Control-Allow-Headers": self.acah_header,
            },
        }


# ── Rule definitions ─────────────────────────────────────────────────────

ORIGIN_VALIDATION_RULE = CORSDefenseRule(
    name="Origin Whitelist Validation",
    technique=CORSDefenseTechnique.ORIGIN_VALIDATION,
    description="Allow only explicitly trusted domains in Access-Control-Allow-Origin.",
    issue_types=["Wildcard Origin Allowed", "Origin Reflection"],
    action=CORSDefenseAction.BLOCKED,
    priority=20,
    remediation=(
        "Replace 'Access-Control-Allow-Origin: *' with explicit trusted origins. "
        "Do not reflect the request Origin header back without validation."
    ),
)

CREDENTIAL_PROTECTION_RULE = CORSDefenseRule(
    name="Credential-Origin Restriction",
    technique=CORSDefenseTechnique.CREDENTIAL_PROTECTION,
    description=(
        "When Access-Control-Allow-Credentials is true, the server must not "
        "use a wildcard origin. Enforce a specific trusted origin."
    ),
    issue_types=["Credentials with Wildcard Origin"],
    action=CORSDefenseAction.BLOCKED,
    priority=25,
    remediation=(
        "Set Access-Control-Allow-Origin to a specific trusted domain "
        "when Access-Control-Allow-Credentials: true."
    ),
)

NULL_ORIGIN_PROTECTION_RULE = CORSDefenseRule(
    name="Null Origin Rejection",
    technique=CORSDefenseTechnique.NULL_ORIGIN_PROTECTION,
    description="Reject requests where the Origin header is 'null'.",
    issue_types=["Null Origin Acceptance"],
    action=CORSDefenseAction.BLOCKED,
    priority=18,
    remediation="Never include 'null' in Access-Control-Allow-Origin.",
)

SUBDOMAIN_RESTRICTION_RULE = CORSDefenseRule(
    name="Subdomain Trust Restriction",
    technique=CORSDefenseTechnique.SUBDOMAIN_RESTRICTION,
    description=(
        "Avoid trusting all subdomains automatically. Only allow "
        "specific, verified subdomains."
    ),
    issue_types=["Subdomain Trust Misconfiguration"],
    action=CORSDefenseAction.HARDENED,
    priority=15,
    remediation=(
        "Replace wildcard subdomain matching (*.example.com) with an "
        "explicit whitelist of trusted subdomains."
    ),
)

PROTOCOL_ENFORCEMENT_RULE = CORSDefenseRule(
    name="HTTPS Protocol Enforcement",
    technique=CORSDefenseTechnique.PROTOCOL_ENFORCEMENT,
    description="Only allow HTTPS origins; reject HTTP and other insecure protocols.",
    issue_types=["Insecure Protocol Trust"],
    action=CORSDefenseAction.ENFORCED,
    priority=14,
    remediation="Only accept origins with https:// scheme in CORS responses.",
)

PREFLIGHT_VALIDATION_RULE = CORSDefenseRule(
    name="Preflight Request Hardening",
    technique=CORSDefenseTechnique.PREFLIGHT_VALIDATION,
    description=(
        "Validate OPTIONS preflight requests. Restrict allowed methods "
        "and headers to what the application actually needs."
    ),
    issue_types=["Preflight Misconfiguration"],
    action=CORSDefenseAction.HARDENED,
    priority=12,
    remediation=(
        "Respond to OPTIONS with minimal Access-Control-Allow-Methods "
        "and Access-Control-Allow-Headers. Remove overly permissive values."
    ),
)

SENSITIVE_DATA_PROTECTION_RULE = CORSDefenseRule(
    name="Sensitive Data CORS Protection",
    technique=CORSDefenseTechnique.SENSITIVE_DATA_PROTECTION,
    description=(
        "Endpoints returning sensitive data must enforce strict origin "
        "restrictions, authentication, and token validation."
    ),
    issue_types=["Sensitive Data Exposure via CORS"],
    action=CORSDefenseAction.BLOCKED,
    priority=22,
    remediation=(
        "Require authentication on sensitive endpoints. Set strict "
        "Access-Control-Allow-Origin instead of *."
    ),
)

HEADER_VALIDATION_RULE = CORSDefenseRule(
    name="Allowed Header Restriction",
    technique=CORSDefenseTechnique.HEADER_VALIDATION,
    description=(
        "Only allow safe, necessary headers in Access-Control-Allow-Headers. "
        "Reject wildcards and dangerous headers like Authorization unless required."
    ),
    issue_types=["Insecure Allowed Headers"],
    action=CORSDefenseAction.HARDENED,
    priority=16,
    remediation=(
        "Remove '*' from Access-Control-Allow-Headers. Explicitly list only "
        "the headers your application requires."
    ),
)

JSON_API_HARDENING_RULE = CORSDefenseRule(
    name="JSON API CORS Hardening",
    technique=CORSDefenseTechnique.JSON_API_HARDENING,
    description=(
        "JSON API endpoints must not expose responses to arbitrary origins. "
        "Restrict CORS to known consumer domains."
    ),
    issue_types=["Improper CORS with JSON APIs"],
    action=CORSDefenseAction.BLOCKED,
    priority=19,
    remediation=(
        "Set Access-Control-Allow-Origin to the specific frontend domain "
        "that consumes the JSON API."
    ),
)


# ── Collected rule set ────────────────────────────────────────────────────

ALL_CORS_DEFENSE_RULES: List[CORSDefenseRule] = sorted(
    [
        ORIGIN_VALIDATION_RULE,
        CREDENTIAL_PROTECTION_RULE,
        NULL_ORIGIN_PROTECTION_RULE,
        SUBDOMAIN_RESTRICTION_RULE,
        PROTOCOL_ENFORCEMENT_RULE,
        PREFLIGHT_VALIDATION_RULE,
        SENSITIVE_DATA_PROTECTION_RULE,
        HEADER_VALIDATION_RULE,
        JSON_API_HARDENING_RULE,
    ],
    key=lambda r: r.priority,
    reverse=True,
)
