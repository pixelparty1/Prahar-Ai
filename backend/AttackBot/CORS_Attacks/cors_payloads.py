"""
cors_payloads.py
----------------
Central repository of CORS test origin payloads organized by category.
All payloads are Origin header values used for **detection only** — the bot
only reads response headers and never modifies server state.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class CORSOriginPayload:
    """A named group of CORS test origins."""
    name: str
    description: str
    origins: List[str] = field(default_factory=list)


# ── Malicious external origins ────────────────────────────────────────────
MALICIOUS_ORIGINS = CORSOriginPayload(
    name="Malicious External Origins",
    description="Origins from attacker-controlled domains to test origin reflection.",
    origins=[
        "https://attacker.com",
        "https://evil.com",
        "https://malicious-site.com",
        "https://hacker.org",
        "https://attack-vector.net",
    ],
)

# ── Null origin payloads ─────────────────────────────────────────────────
NULL_ORIGINS = CORSOriginPayload(
    name="Null Origin",
    description="Null origin used by sandboxed iframes, data: URIs, and file:// pages.",
    origins=[
        "null",
    ],
)

# ── Localhost / internal origins ─────────────────────────────────────────
LOCALHOST_ORIGINS = CORSOriginPayload(
    name="Localhost Origins",
    description="Localhost and internal network origins that may be trusted incorrectly.",
    origins=[
        "http://localhost",
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://0.0.0.0",
    ],
)

# ── Subdomain / prefix variation origins ─────────────────────────────────
SUBDOMAIN_ORIGINS = CORSOriginPayload(
    name="Subdomain Variations",
    description="Origins testing subdomain trust and suffix matching bypasses.",
    origins=[
        "https://sub.attacker.com",
        "https://api.attacker.com",
        "https://evil.sub.attacker.com",
    ],
)

# ── Protocol / scheme variation origins ──────────────────────────────────
PROTOCOL_ORIGINS = CORSOriginPayload(
    name="Protocol Variations",
    description="Origins testing acceptance of non-standard or file:// schemes.",
    origins=[
        "file://",
        "http://attacker.com",
    ],
)


# ── Convenience helpers ──────────────────────────────────────────────────

ALL_CORS_ORIGINS: List[CORSOriginPayload] = [
    MALICIOUS_ORIGINS,
    NULL_ORIGINS,
    LOCALHOST_ORIGINS,
    SUBDOMAIN_ORIGINS,
    PROTOCOL_ORIGINS,
]


def get_all_origins() -> List[str]:
    """Return a flat list of every test origin."""
    origins: List[str] = []
    for cat in ALL_CORS_ORIGINS:
        origins.extend(cat.origins)
    return origins


def get_origins_by_category(name: str) -> List[str]:
    """Return origins for a single category by name (case-insensitive)."""
    for cat in ALL_CORS_ORIGINS:
        if cat.name.lower() == name.lower():
            return cat.origins
    return []
