"""
xss_defense_rules.py
--------------------
Central repository of XSS defense rules and data structures.

Each rule maps to a real-world XSS mitigation technique and defines
patterns that match against XSS attack findings produced by the
XSSAttackBot.

The DefendBot does NOT modify any AttackBot code — it only reads
the findings produced by the XSS scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Defense action classifications ────────────────────────────────────────

class XSSDefenseAction(str, Enum):
    BLOCKED    = "Blocked"
    SANITIZED  = "Sanitized"
    ENCODED    = "Encoded"
    RESTRICTED = "Restricted"
    ALLOWED    = "Allowed"


# ── Defense technique enumeration ─────────────────────────────────────────

class XSSDefenseTechnique(str, Enum):
    INPUT_SANITIZATION       = "Input Sanitization"
    OUTPUT_ENCODING          = "Output Encoding"
    CONTENT_SECURITY_POLICY  = "Content Security Policy"
    EVENT_HANDLER_BLOCKING   = "Event Handler Blocking"
    DOM_MANIPULATION_PROTECTION = "DOM Manipulation Protection"
    JS_URI_BLOCKING          = "JavaScript URI Blocking"
    TEMPLATE_ENGINE_ESCAPING = "Template Engine Escaping"
    STORED_XSS_PROTECTION    = "Stored XSS Protection"
    HEADER_VALIDATION        = "Allowed Header Validation"
    POLYGLOT_FILTER          = "Polyglot Filter"


# ── Payload pattern sets for matching ─────────────────────────────────────

# Patterns indicating script injection (input sanitization targets)
_SCRIPT_PATTERNS = [
    re.compile(r"<\s*script", re.I),
    re.compile(r"<\s*/\s*script", re.I),
    re.compile(r"<\s*iframe", re.I),
    re.compile(r"<\s*object", re.I),
    re.compile(r"<\s*embed", re.I),
    re.compile(r"<\s*svg", re.I),
    re.compile(r"<\s*img\b", re.I),
    re.compile(r"<\s*body\b", re.I),
    re.compile(r"<\s*input\b", re.I),
    re.compile(r"<\s*details\b", re.I),
    re.compile(r"<\s*video\b", re.I),
    re.compile(r"<\s*audio\b", re.I),
    re.compile(r"<\s*marquee\b", re.I),
    re.compile(r"<\s*math\b", re.I),
]

# Event handler patterns
_EVENT_HANDLER_PATTERNS = [
    re.compile(r"\bon\w+\s*=", re.I),          # onerror=, onload=, onmouseover=, etc.
    re.compile(r"autofocus\s+onfocus", re.I),
    re.compile(r"ontoggle\s*=", re.I),
]

# JavaScript URI patterns
_JS_URI_PATTERNS = [
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"data\s*:\s*text/html", re.I),
    re.compile(r"vbscript\s*:", re.I),
]

# DOM sink patterns (for DOM-based XSS)
_DOM_SINK_PATTERNS = [
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"\.outerHTML\s*=", re.I),
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"document\.writeln\s*\(", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"setTimeout\s*\(", re.I),
    re.compile(r"setInterval\s*\(", re.I),
    re.compile(r"insertAdjacentHTML\s*\(", re.I),
]

# Template injection patterns
_TEMPLATE_PATTERNS = [
    re.compile(r"\{\{.*\}\}"),              # Jinja2 / Angular / Vue
    re.compile(r"\$\{.*\}"),                # JS template literals
    re.compile(r"<%.*%>"),                  # EJS / ERB
    re.compile(r"#\{.*\}"),                 # Ruby / Pug
]

# Encoding bypass / mutation patterns
_MUTATION_PATTERNS = [
    re.compile(r"&#\d+;"),                  # HTML entities (decimal)
    re.compile(r"&#x[0-9a-fA-F]+;"),        # HTML entities (hex)
    re.compile(r"\\x[0-9a-fA-F]{2}"),        # JS hex escape
    re.compile(r"\\u[0-9a-fA-F]{4}"),        # JS unicode escape
    re.compile(r"%[0-9a-fA-F]{2}"),          # URL encoding
    re.compile(r"String\.fromCharCode", re.I),
    re.compile(r"atob\s*\(", re.I),
]


# ── XSS defense rule ─────────────────────────────────────────────────────

@dataclass
class XSSDefenseRule:
    """
    A single XSS defense rule that matches attack patterns.
    """
    name: str
    technique: XSSDefenseTechnique
    description: str
    xss_types: List[str]
    payload_patterns: List[re.Pattern] = field(default_factory=list)
    action: XSSDefenseAction = XSSDefenseAction.SANITIZED
    priority: int = 10
    remediation: str = ""


# ── XSS defense verdict ──────────────────────────────────────────────────

@dataclass
class XSSDefenseVerdict:
    """
    Result of evaluating an XSS attack finding against defense rules.
    """
    endpoint: str
    parameter: str
    method: str
    payload: str
    xss_type: str
    severity: str
    triggered_rules: List[XSSDefenseRule] = field(default_factory=list)
    action: XSSDefenseAction = XSSDefenseAction.ALLOWED
    technique: Optional[XSSDefenseTechnique] = None
    explanation: str = ""
    safe_output_example: str = ""
    evidence: str = ""
    confidence: str = ""

    @property
    def blocked(self) -> bool:
        return self.action in (
            XSSDefenseAction.BLOCKED,
            XSSDefenseAction.SANITIZED,
            XSSDefenseAction.ENCODED,
            XSSDefenseAction.RESTRICTED,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "xss_type": self.xss_type,
            "severity": self.severity,
            "action": self.action.value,
            "technique": self.technique.value if self.technique else None,
            "explanation": self.explanation,
            "safe_output_example": self.safe_output_example,
            "triggered_rules": [r.name for r in self.triggered_rules],
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


# ── Rule definitions ─────────────────────────────────────────────────────

INPUT_SANITIZATION_RULE = XSSDefenseRule(
    name="HTML Input Sanitization",
    technique=XSSDefenseTechnique.INPUT_SANITIZATION,
    description=(
        "Detect and sanitize dangerous HTML/JavaScript patterns in user input "
        "before rendering. Strips <script>, <iframe>, <svg>, and similar tags."
    ),
    xss_types=["Reflected XSS", "Polyglot XSS", "Mutation XSS"],
    payload_patterns=_SCRIPT_PATTERNS,
    action=XSSDefenseAction.SANITIZED,
    priority=20,
    remediation="Sanitize all user input with an allowlist-based HTML sanitizer.",
)

OUTPUT_ENCODING_RULE = XSSDefenseRule(
    name="Output Encoding",
    technique=XSSDefenseTechnique.OUTPUT_ENCODING,
    description=(
        "Encode HTML special characters before rendering user-generated "
        "content in the browser. Converts < > \" & to entities."
    ),
    xss_types=["Reflected XSS", "Stored XSS", "Polyglot XSS"],
    payload_patterns=_SCRIPT_PATTERNS + _MUTATION_PATTERNS,
    action=XSSDefenseAction.ENCODED,
    priority=22,
    remediation="Apply context-aware output encoding (HTML, JS, URL, CSS).",
)

CSP_RULE = XSSDefenseRule(
    name="Content Security Policy Enforcement",
    technique=XSSDefenseTechnique.CONTENT_SECURITY_POLICY,
    description=(
        "Enforce a strict Content-Security-Policy header that blocks inline "
        "scripts and restricts script sources to 'self'."
    ),
    xss_types=[
        "Reflected XSS", "Stored XSS", "DOM-Based XSS", "Blind XSS",
        "Event Handler XSS", "Attribute Injection XSS", "JavaScript URI XSS",
        "Template Injection XSS", "Mutation XSS", "Polyglot XSS",
    ],
    payload_patterns=[],  # CSP is a blanket defense — matches all XSS types
    action=XSSDefenseAction.BLOCKED,
    priority=10,
    remediation="Content-Security-Policy: script-src 'self'; object-src 'none'",
)

EVENT_HANDLER_BLOCKING_RULE = XSSDefenseRule(
    name="Event Handler Attribute Blocking",
    technique=XSSDefenseTechnique.EVENT_HANDLER_BLOCKING,
    description=(
        "Detect and neutralize HTML attributes containing event handlers "
        "(onerror, onload, onmouseover, onfocus, etc.)."
    ),
    xss_types=["Event Handler XSS", "Attribute Injection XSS"],
    payload_patterns=_EVENT_HANDLER_PATTERNS,
    action=XSSDefenseAction.SANITIZED,
    priority=18,
    remediation="Strip all on* attributes from user-supplied HTML content.",
)

DOM_PROTECTION_RULE = XSSDefenseRule(
    name="DOM Manipulation Protection",
    technique=XSSDefenseTechnique.DOM_MANIPULATION_PROTECTION,
    description=(
        "Detect dangerous DOM APIs (innerHTML, document.write, eval) and "
        "simulate replacing them with safer alternatives (textContent, "
        "createElement, JSON.parse)."
    ),
    xss_types=["DOM-Based XSS"],
    payload_patterns=_DOM_SINK_PATTERNS,
    action=XSSDefenseAction.RESTRICTED,
    priority=17,
    remediation="Use textContent instead of innerHTML. Avoid eval() and document.write().",
)

JS_URI_BLOCKING_RULE = XSSDefenseRule(
    name="JavaScript URI Blocking",
    technique=XSSDefenseTechnique.JS_URI_BLOCKING,
    description=(
        "Detect and block malicious javascript:, data:text/html, and "
        "vbscript: URIs in href, src, and action attributes."
    ),
    xss_types=["JavaScript URI XSS"],
    payload_patterns=_JS_URI_PATTERNS,
    action=XSSDefenseAction.BLOCKED,
    priority=19,
    remediation="Validate URL schemes; only allow http:// and https:// in user-supplied links.",
)

TEMPLATE_ESCAPING_RULE = XSSDefenseRule(
    name="Template Engine Auto-Escaping",
    technique=XSSDefenseTechnique.TEMPLATE_ENGINE_ESCAPING,
    description=(
        "Detect unsafe template rendering of user input. Simulate "
        "automatic escaping in template engines (Jinja2 autoescape, "
        "Angular sanitizer, Vue v-text)."
    ),
    xss_types=["Template Injection XSS"],
    payload_patterns=_TEMPLATE_PATTERNS,
    action=XSSDefenseAction.ENCODED,
    priority=16,
    remediation="Enable autoescape in template engines. Use |e filter in Jinja2.",
)

STORED_XSS_PROTECTION_RULE = XSSDefenseRule(
    name="Stored Content Sanitization",
    technique=XSSDefenseTechnique.STORED_XSS_PROTECTION,
    description=(
        "Sanitize user input before storing in the database and again "
        "before rendering, preventing persistent XSS."
    ),
    xss_types=["Stored XSS", "Blind XSS"],
    payload_patterns=_SCRIPT_PATTERNS + _EVENT_HANDLER_PATTERNS,
    action=XSSDefenseAction.SANITIZED,
    priority=23,
    remediation="Sanitize on input AND encode on output. Never trust stored content.",
)

POLYGLOT_FILTER_RULE = XSSDefenseRule(
    name="Polyglot Payload Filter",
    technique=XSSDefenseTechnique.POLYGLOT_FILTER,
    description=(
        "Detect complex polyglot payloads that combine multiple XSS vectors "
        "in a single input. Apply layered sanitization and encoding."
    ),
    xss_types=["Polyglot XSS", "Mutation XSS"],
    payload_patterns=_MUTATION_PATTERNS + _SCRIPT_PATTERNS + _EVENT_HANDLER_PATTERNS,
    action=XSSDefenseAction.BLOCKED,
    priority=24,
    remediation="Use layered defense: sanitize + encode + CSP. Test with polyglot payloads.",
)


# ── Collected rule set ────────────────────────────────────────────────────

ALL_XSS_DEFENSE_RULES: List[XSSDefenseRule] = sorted(
    [
        INPUT_SANITIZATION_RULE,
        OUTPUT_ENCODING_RULE,
        CSP_RULE,
        EVENT_HANDLER_BLOCKING_RULE,
        DOM_PROTECTION_RULE,
        JS_URI_BLOCKING_RULE,
        TEMPLATE_ESCAPING_RULE,
        STORED_XSS_PROTECTION_RULE,
        POLYGLOT_FILTER_RULE,
    ],
    key=lambda r: r.priority,
    reverse=True,
)
