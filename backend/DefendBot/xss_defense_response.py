"""
xss_defense_response.py
-----------------------
Evaluation engine that matches XSSAttackEvents against defense rules
and produces XSSDefenseVerdicts.
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional

from .xss_defense_monitor import XSSAttackEvent
from .xss_defense_rules import (
    ALL_XSS_DEFENSE_RULES,
    XSSDefenseAction,
    XSSDefenseRule,
    XSSDefenseTechnique,
    XSSDefenseVerdict,
)


# ── Technique-specific explanation templates ──────────────────────────────

_TECHNIQUE_EXPLANATIONS: Dict[XSSDefenseTechnique, str] = {
    XSSDefenseTechnique.INPUT_SANITIZATION: (
        "Dangerous HTML tags stripped from user input. "
        "Payload neutralised before reaching the DOM."
    ),
    XSSDefenseTechnique.OUTPUT_ENCODING: (
        "HTML special characters encoded before rendering. "
        "< → &lt;  > → &gt;  \" → &quot;  & → &amp;"
    ),
    XSSDefenseTechnique.CONTENT_SECURITY_POLICY: (
        "CSP header blocked inline script execution. "
        "Content-Security-Policy: script-src 'self'; object-src 'none'"
    ),
    XSSDefenseTechnique.EVENT_HANDLER_BLOCKING: (
        "Event handler attribute removed from user-supplied HTML. "
        "All on* attributes stripped during sanitisation."
    ),
    XSSDefenseTechnique.DOM_MANIPULATION_PROTECTION: (
        "Dangerous DOM API usage detected and replaced. "
        "innerHTML → textContent, document.write → createElement."
    ),
    XSSDefenseTechnique.JS_URI_BLOCKING: (
        "Malicious javascript: / data: URI blocked. "
        "Only http:// and https:// protocols are allowed."
    ),
    XSSDefenseTechnique.TEMPLATE_ENGINE_ESCAPING: (
        "Template engine auto-escaping activated. "
        "All dynamic variables escaped before rendering."
    ),
    XSSDefenseTechnique.STORED_XSS_PROTECTION: (
        "Input sanitised before database storage AND encoded on output. "
        "Double-layer protection prevents persistent XSS execution."
    ),
    XSSDefenseTechnique.HEADER_VALIDATION: (
        "Allowed header validation applied. "
        "Only safe, standard headers permitted."
    ),
    XSSDefenseTechnique.POLYGLOT_FILTER: (
        "Layered defence applied to polyglot payload. "
        "Sanitisation + encoding + CSP combined for multi-vector protection."
    ),
}


# ── Safe output examples ─────────────────────────────────────────────────

def _make_safe_output(payload: str, technique: XSSDefenseTechnique) -> str:
    """Return a human-readable example of what the payload looks like after defense."""
    if technique in (
        XSSDefenseTechnique.OUTPUT_ENCODING,
        XSSDefenseTechnique.TEMPLATE_ENGINE_ESCAPING,
    ):
        return html.escape(payload[:120])

    if technique == XSSDefenseTechnique.INPUT_SANITIZATION:
        stripped = re.sub(r"<[^>]+>", "", payload)
        return stripped[:120] or "[empty after sanitisation]"

    if technique == XSSDefenseTechnique.EVENT_HANDLER_BLOCKING:
        stripped = re.sub(r"\bon\w+\s*=\s*['\"][^'\"]*['\"]", "", payload, flags=re.I)
        stripped = re.sub(r"\bon\w+\s*=\s*\S+", "", stripped, flags=re.I)
        return stripped[:120] or "[empty after stripping event handlers]"

    if technique == XSSDefenseTechnique.JS_URI_BLOCKING:
        return "[URI blocked: only http/https allowed]"

    if technique == XSSDefenseTechnique.DOM_MANIPULATION_PROTECTION:
        return "[DOM sink neutralised: safe API used instead]"

    if technique == XSSDefenseTechnique.STORED_XSS_PROTECTION:
        return html.escape(re.sub(r"<[^>]+>", "", payload)[:120]) or "[sanitised before storage]"

    if technique == XSSDefenseTechnique.CONTENT_SECURITY_POLICY:
        return "[inline script blocked by CSP]"

    if technique == XSSDefenseTechnique.POLYGLOT_FILTER:
        return "[multi-vector payload filtered by layered defence]"

    return "[payload neutralised]"


# ── Defense engine ────────────────────────────────────────────────────────

class XSSDefenseEngine:
    """
    Evaluates XSSAttackEvents against defense rules and produces verdicts.
    """

    def __init__(self, rules: Optional[List[XSSDefenseRule]] = None) -> None:
        self._rules = rules or list(ALL_XSS_DEFENSE_RULES)
        self._verdicts: List[XSSDefenseVerdict] = []

    # ── evaluation ────────────────────────────────────────────────────

    def evaluate(self, event: XSSAttackEvent) -> XSSDefenseVerdict:
        matched_rules: List[XSSDefenseRule] = []

        for rule in self._rules:
            # Match by XSS type
            if event.xss_type in rule.xss_types:
                # If rule has patterns, verify payload match
                if rule.payload_patterns:
                    if any(p.search(event.payload) for p in rule.payload_patterns):
                        matched_rules.append(rule)
                else:
                    # CSP-style blanket rules — match on type alone
                    matched_rules.append(rule)

        if matched_rules:
            # Pick the highest-priority rule
            best = max(matched_rules, key=lambda r: r.priority)
            technique = best.technique
            explanation = _TECHNIQUE_EXPLANATIONS.get(
                technique,
                f"Defense applied: {best.description}",
            )
            safe_output = _make_safe_output(event.payload, technique)

            verdict = XSSDefenseVerdict(
                endpoint=event.endpoint,
                parameter=event.parameter,
                method=event.method,
                payload=event.payload,
                xss_type=event.xss_type,
                severity=event.severity,
                triggered_rules=matched_rules,
                action=best.action,
                technique=technique,
                explanation=explanation,
                safe_output_example=safe_output,
                evidence=event.evidence,
                confidence=event.confidence,
            )
        else:
            verdict = XSSDefenseVerdict(
                endpoint=event.endpoint,
                parameter=event.parameter,
                method=event.method,
                payload=event.payload,
                xss_type=event.xss_type,
                severity=event.severity,
                action=XSSDefenseAction.ALLOWED,
                explanation="No matching defense rule. Manual review recommended.",
                evidence=event.evidence,
                confidence=event.confidence,
            )

        self._verdicts.append(verdict)
        return verdict

    # ── accessors ─────────────────────────────────────────────────────

    @property
    def verdicts(self) -> List[XSSDefenseVerdict]:
        return list(self._verdicts)

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._verdicts)
        blocked = sum(1 for v in self._verdicts if v.blocked)
        by_technique: Dict[str, int] = {}
        by_xss_type: Dict[str, int] = {}
        by_action: Dict[str, int] = {}

        for v in self._verdicts:
            if v.technique:
                t = v.technique.value
                by_technique[t] = by_technique.get(t, 0) + 1
            x = v.xss_type
            by_xss_type[x] = by_xss_type.get(x, 0) + 1
            a = v.action.value
            by_action[a] = by_action.get(a, 0) + 1

        return {
            "total_evaluated": total,
            "total_mitigated": blocked,
            "total_allowed": total - blocked,
            "defense_rate": round(blocked / total * 100, 1) if total else 0.0,
            "by_technique": by_technique,
            "by_xss_type": by_xss_type,
            "by_action": by_action,
        }

    def reset(self) -> None:
        self._verdicts.clear()
