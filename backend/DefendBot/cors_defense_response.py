"""
cors_defense_response.py
------------------------
CORS defense engine that evaluates each CORS attack event against
the defense rules and produces a verdict.

The engine simulates real-world CORS hardening techniques:
  • Origin whitelist validation
  • Credential-origin restriction
  • Null origin rejection
  • Subdomain trust restriction
  • HTTPS protocol enforcement
  • Preflight request hardening
  • Sensitive data protection
  • Allowed header validation
  • JSON API CORS hardening
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any, Dict, List, Optional

from .cors_defense_monitor import CORSAttackEvent
from .cors_defense_rules import (
    ALL_CORS_DEFENSE_RULES,
    CORSDefenseAction,
    CORSDefenseRule,
    CORSDefenseTechnique,
    CORSDefenseVerdict,
)

logger = logging.getLogger(__name__)


# ── Trusted origin whitelist (simulated) ──────────────────────────────────

_TRUSTED_ORIGINS = {
    "https://trusted-domain.com",
    "https://app.trusted-domain.com",
    "https://www.trusted-domain.com",
}

_SAFE_HEADERS = {
    "Accept", "Accept-Language", "Content-Language", "Content-Type",
    "DPR", "Downlink", "Save-Data", "Viewport-Width", "Width",
}

_SAFE_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}


class CORSDefenseEngine:
    """
    Evaluates CORS attack events against defense rules and produces verdicts.

    Thread-safe — can be called from multiple scan workers concurrently.
    """

    def __init__(self, rules: Optional[List[CORSDefenseRule]] = None):
        self._rules = rules or list(ALL_CORS_DEFENSE_RULES)
        self._verdicts: List[CORSDefenseVerdict] = []
        self._lock = threading.Lock()

    @property
    def verdicts(self) -> List[CORSDefenseVerdict]:
        with self._lock:
            return list(self._verdicts)

    # ── Core evaluation ──────────────────────────────────────────────

    def evaluate(
        self, event: CORSAttackEvent, heavily_targeted: bool = False
    ) -> CORSDefenseVerdict:
        """
        Evaluate a single CORS attack event and return a defense verdict.
        """
        triggered: List[CORSDefenseRule] = []

        # Normalize issue_type for matching (CORSIssueType may be enum or str)
        issue_str = str(event.issue_type)
        if hasattr(event.issue_type, "value"):
            issue_str = event.issue_type.value

        for rule in self._rules:
            if issue_str in rule.issue_types:
                triggered.append(rule)

        if not triggered:
            verdict = CORSDefenseVerdict(
                endpoint=event.endpoint,
                method=event.method,
                origin_sent=event.origin_sent,
                issue_type=issue_str,
                severity=event.severity,
                action=CORSDefenseAction.ALLOWED,
                technique=None,
                explanation="No defense rule matched this CORS pattern.",
                acao_header=event.acao_header,
                acac_header=event.acac_header,
                acam_header=event.acam_header,
                acah_header=event.acah_header,
            )
        else:
            top_rule = triggered[0]  # highest priority (already sorted)
            explanation = self._build_explanation(event, top_rule, heavily_targeted)
            safe_header = self._generate_safe_headers(event, top_rule)

            verdict = CORSDefenseVerdict(
                endpoint=event.endpoint,
                method=event.method,
                origin_sent=event.origin_sent,
                issue_type=issue_str,
                severity=event.severity,
                triggered_rules=triggered,
                action=top_rule.action,
                technique=top_rule.technique,
                explanation=explanation,
                safe_header_example=safe_header,
                acao_header=event.acao_header,
                acac_header=event.acac_header,
                acam_header=event.acam_header,
                acah_header=event.acah_header,
            )

        with self._lock:
            self._verdicts.append(verdict)

        return verdict

    # ── Explanation builder ───────────────────────────────────────────

    def _build_explanation(
        self,
        event: CORSAttackEvent,
        rule: CORSDefenseRule,
        heavily_targeted: bool,
    ) -> str:
        """Build a human-readable explanation of the defense action."""
        tech = rule.technique
        origin = event.origin_sent or "unknown"

        explanations = {
            CORSDefenseTechnique.ORIGIN_VALIDATION: (
                f"Origin '{origin}' is not in the trusted whitelist. "
                f"Request blocked. Only explicitly approved origins are allowed."
            ),
            CORSDefenseTechnique.CREDENTIAL_PROTECTION: (
                f"Credentials (Access-Control-Allow-Credentials: true) cannot be "
                f"combined with a wildcard origin. Origin '{origin}' rejected. "
                f"A specific trusted origin must be set."
            ),
            CORSDefenseTechnique.NULL_ORIGIN_PROTECTION: (
                f"Null origin request rejected. 'null' origins are used in "
                f"sandboxed iframes and data: URIs and must not be trusted."
            ),
            CORSDefenseTechnique.SUBDOMAIN_RESTRICTION: (
                f"Origin '{origin}' matches a wildcard subdomain pattern. "
                f"Hardened: only specific verified subdomains are allowed, "
                f"not *.example.com patterns."
            ),
            CORSDefenseTechnique.PROTOCOL_ENFORCEMENT: (
                f"Origin '{origin}' uses an insecure protocol. "
                f"Only HTTPS origins are accepted. HTTP and file:// rejected."
            ),
            CORSDefenseTechnique.PREFLIGHT_VALIDATION: (
                f"Preflight (OPTIONS) response at {event.endpoint} is overly "
                f"permissive. Hardened: restricted allowed methods to "
                f"{', '.join(_SAFE_METHODS)} and headers to safe defaults."
            ),
            CORSDefenseTechnique.SENSITIVE_DATA_PROTECTION: (
                f"Endpoint {event.endpoint} returns sensitive data with open CORS. "
                f"Blocked: authentication enforcement and strict origin restriction applied."
            ),
            CORSDefenseTechnique.HEADER_VALIDATION: (
                f"Access-Control-Allow-Headers is too permissive "
                f"('{event.acah_header}'). Hardened: only safe headers "
                f"({', '.join(sorted(_SAFE_HEADERS)[:4])}, ...) are allowed."
            ),
            CORSDefenseTechnique.JSON_API_HARDENING: (
                f"JSON API at {event.endpoint} exposes data to origin '{origin}'. "
                f"Blocked: CORS restricted to known consumer domains only."
            ),
        }

        explanation = explanations.get(
            tech,
            f"Defense rule '{rule.name}' triggered for {event.issue_type}.",
        )

        if heavily_targeted:
            explanation += (
                f" [WARNING] Endpoint {event.endpoint} is under heavy CORS probing — "
                f"elevated monitoring applied."
            )

        return explanation

    # ── Safe header example generator ─────────────────────────────────

    @staticmethod
    def _generate_safe_headers(
        event: CORSAttackEvent, rule: CORSDefenseRule
    ) -> str:
        """Generate an example of secure CORS response headers."""
        tech = rule.technique

        if tech == CORSDefenseTechnique.ORIGIN_VALIDATION:
            return (
                "Access-Control-Allow-Origin: https://trusted-domain.com\n"
                "Vary: Origin"
            )

        if tech == CORSDefenseTechnique.CREDENTIAL_PROTECTION:
            return (
                "Access-Control-Allow-Origin: https://trusted-domain.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "Vary: Origin"
            )

        if tech == CORSDefenseTechnique.NULL_ORIGIN_PROTECTION:
            return (
                "# Do not include 'null' in Access-Control-Allow-Origin\n"
                "Access-Control-Allow-Origin: https://trusted-domain.com"
            )

        if tech == CORSDefenseTechnique.SUBDOMAIN_RESTRICTION:
            return (
                "# Whitelist specific subdomains instead of *.example.com\n"
                "Access-Control-Allow-Origin: https://app.trusted-domain.com\n"
                "Vary: Origin"
            )

        if tech == CORSDefenseTechnique.PROTOCOL_ENFORCEMENT:
            return (
                "# Only accept HTTPS origins\n"
                "Access-Control-Allow-Origin: https://trusted-domain.com"
            )

        if tech == CORSDefenseTechnique.PREFLIGHT_VALIDATION:
            return (
                "Access-Control-Allow-Methods: GET, POST\n"
                "Access-Control-Allow-Headers: Content-Type\n"
                "Access-Control-Max-Age: 86400"
            )

        if tech == CORSDefenseTechnique.SENSITIVE_DATA_PROTECTION:
            return (
                "Access-Control-Allow-Origin: https://trusted-domain.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "# Require Authorization header for sensitive endpoints"
            )

        if tech == CORSDefenseTechnique.HEADER_VALIDATION:
            return (
                "Access-Control-Allow-Headers: Content-Type, Accept\n"
                "# Do NOT use * or allow Authorization without explicit need"
            )

        if tech == CORSDefenseTechnique.JSON_API_HARDENING:
            return (
                "Access-Control-Allow-Origin: https://trusted-domain.com\n"
                "Content-Type: application/json\n"
                "Vary: Origin"
            )

        return "Access-Control-Allow-Origin: https://trusted-domain.com"

    # ── Result accessors ──────────────────────────────────────────────

    def get_verdicts_as_dicts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [v.to_dict() for v in self._verdicts]

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._verdicts)
            blocked = sum(1 for v in self._verdicts if v.action == CORSDefenseAction.BLOCKED)
            hardened = sum(1 for v in self._verdicts if v.action == CORSDefenseAction.HARDENED)
            enforced = sum(1 for v in self._verdicts if v.action == CORSDefenseAction.ENFORCED)
            allowed = sum(1 for v in self._verdicts if v.action == CORSDefenseAction.ALLOWED)

            by_technique: Dict[str, int] = {}
            by_action: Dict[str, int] = {}
            for v in self._verdicts:
                if v.technique:
                    tech_name = v.technique.value
                    by_technique[tech_name] = by_technique.get(tech_name, 0) + 1
                act_name = v.action.value
                by_action[act_name] = by_action.get(act_name, 0) + 1

            mitigated = blocked + hardened + enforced
            defense_rate = round((mitigated / total) * 100, 1) if total else 0.0

            return {
                "total_attacks_analyzed": total,
                "attacks_blocked": blocked,
                "attacks_hardened": hardened,
                "attacks_enforced": enforced,
                "attacks_mitigated": mitigated,
                "attacks_allowed": allowed,
                "defense_rate": defense_rate,
                "by_technique": by_technique,
                "by_action": by_action,
            }

    def reset(self) -> None:
        with self._lock:
            self._verdicts.clear()
