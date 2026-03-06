# XSS_Attacks sub-package
# Re-exports key symbols for use via AttackBot.XSS_Attacks.*

from .xss_payloads import (
    XSSPayloadCategory,
    ALL_XSS_CATEGORIES,
    REFLECTED_PAYLOADS,
    STORED_PAYLOADS,
    EVENT_HANDLER_PAYLOADS,
    ATTRIBUTE_INJECTION_PAYLOADS,
    JS_URI_PAYLOADS,
    TEMPLATE_INJECTION_PAYLOADS,
    MUTATION_PAYLOADS,
    POLYGLOT_PAYLOADS,
    DOM_PROBE_PAYLOADS,
    BLIND_XSS_PAYLOADS,
)
from .xss_attack_bot import XSSAttackBot, XSSFinding, XSSScanConfig, XSSType

__all__ = [
    "XSSAttackBot",
    "XSSFinding",
    "XSSScanConfig",
    "XSSType",
    "XSSPayloadCategory",
    "ALL_XSS_CATEGORIES",
]
