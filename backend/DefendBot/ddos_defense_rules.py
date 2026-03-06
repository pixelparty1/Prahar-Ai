"""
ddos_defense_rules.py
---------------------
Central repository of DDoS defense rules and data structures.

Each rule maps to a real-world DDoS mitigation strategy and defines
thresholds / patterns for matching against DDoS attack findings
produced by the DDoSAttackBot.

The DefendBot does NOT modify any AttackBot code — it only reads
the findings produced by the DDoS scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Defense action classifications ────────────────────────────────────────

class DDoSDefenseAction(str, Enum):
    BLOCKED          = "Blocked"
    THROTTLED        = "Throttled"
    RATE_LIMITED     = "Rate Limited"
    CONNECTION_LIMITED = "Connection Limited"
    REJECTED         = "Rejected"
    ALLOWED          = "Allowed"


# ── Defense technique enumeration ─────────────────────────────────────────

class DDoSDefenseTechnique(str, Enum):
    RATE_LIMITING             = "Rate Limiting"
    TRAFFIC_THROTTLING        = "Traffic Throttling"
    IP_BLOCKING               = "IP Blocking"
    CONNECTION_LIMITING       = "Connection Limiting"
    REQUEST_SIZE_VALIDATION   = "Request Size Validation"
    UPLOAD_PROTECTION         = "Upload Protection"
    WEBSOCKET_CONNECTION_CTRL = "WebSocket Connection Control"
    API_ABUSE_PROTECTION      = "API Abuse Protection"
    CACHING_PROTECTION        = "Caching Protection"
    DB_QUERY_PROTECTION       = "Database Query Protection"
    RATE_LIMIT_BYPASS_DETECT  = "Rate Limit Bypass Detection"


# ── DDoS defense rule ────────────────────────────────────────────────────

@dataclass
class DDoSDefenseRule:
    """A single DDoS defense rule matching attack patterns."""
    name: str
    technique: DDoSDefenseTechnique
    description: str
    attack_types: List[str]
    action: DDoSDefenseAction = DDoSDefenseAction.BLOCKED
    priority: int = 10
    thresholds: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


# ── DDoS defense verdict ─────────────────────────────────────────────────

@dataclass
class DDoSDefenseVerdict:
    """Result of evaluating a DDoS attack finding against defense rules."""
    attack_type: str
    severity: str
    endpoint: str
    observation: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    triggered_rules: List[DDoSDefenseRule] = field(default_factory=list)
    action: DDoSDefenseAction = DDoSDefenseAction.ALLOWED
    technique: Optional[DDoSDefenseTechnique] = None
    explanation: str = ""

    @property
    def mitigated(self) -> bool:
        return self.action != DDoSDefenseAction.ALLOWED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "observation": self.observation,
            "recommendation": self.recommendation,
            "details": self.details,
            "action": self.action.value,
            "technique": self.technique.value if self.technique else None,
            "explanation": self.explanation,
            "triggered_rules": [r.name for r in self.triggered_rules],
        }


# ── Rule definitions ─────────────────────────────────────────────────────

RATE_LIMITING_RULE = DDoSDefenseRule(
    name="Request Rate Limiting",
    technique=DDoSDefenseTechnique.RATE_LIMITING,
    description=(
        "Detect abnormal request rates from the same source and enforce "
        "per-IP/session rate limits. Requests exceeding the threshold "
        "are rejected with HTTP 429."
    ),
    attack_types=["HTTP Flood"],
    action=DDoSDefenseAction.RATE_LIMITED,
    priority=22,
    thresholds={"max_requests_per_second": 50, "burst_limit": 100},
    remediation="Enforce rate limiting at edge (e.g. nginx limit_req, Cloudflare rate rules).",
)

TRAFFIC_THROTTLING_RULE = DDoSDefenseRule(
    name="Traffic Throttling",
    technique=DDoSDefenseTechnique.TRAFFIC_THROTTLING,
    description=(
        "Detect excessive traffic spikes and slow down or delay "
        "request processing to prevent server overload."
    ),
    attack_types=["HTTP Flood", "Cache Bypass Flood"],
    action=DDoSDefenseAction.THROTTLED,
    priority=18,
    thresholds={"spike_detection_factor": 3.0, "throttle_delay_ms": 500},
    remediation="Configure adaptive traffic throttling in load balancer or CDN.",
)

IP_BLOCKING_RULE = DDoSDefenseRule(
    name="IP Blocking",
    technique=DDoSDefenseTechnique.IP_BLOCKING,
    description=(
        "Detect repeated malicious behaviour from the same source IP "
        "and temporarily block the offending address."
    ),
    attack_types=["HTTP Flood", "Login Brute Force Flood", "Rate Limit Bypass"],
    action=DDoSDefenseAction.BLOCKED,
    priority=25,
    thresholds={"max_violations_before_block": 3, "block_duration_minutes": 15},
    remediation="Implement IP blacklisting with auto-expiry via WAF or fail2ban.",
)

CONNECTION_LIMITING_RULE = DDoSDefenseRule(
    name="Connection Limiting",
    technique=DDoSDefenseTechnique.CONNECTION_LIMITING,
    description=(
        "Detect excessive open connections and enforce per-IP "
        "concurrent connection limits."
    ),
    attack_types=["Slowloris"],
    action=DDoSDefenseAction.CONNECTION_LIMITED,
    priority=23,
    thresholds={"max_connections_per_ip": 10, "idle_timeout_seconds": 30},
    remediation="Set connection limits and idle timeouts (e.g. nginx worker_connections, keepalive_timeout).",
)

REQUEST_SIZE_VALIDATION_RULE = DDoSDefenseRule(
    name="Request Size Validation",
    technique=DDoSDefenseTechnique.REQUEST_SIZE_VALIDATION,
    description=(
        "Detect abnormally large request payloads and reject requests "
        "exceeding defined size limits."
    ),
    attack_types=["Large Payload"],
    action=DDoSDefenseAction.REJECTED,
    priority=21,
    thresholds={"max_body_size_mb": 10, "max_header_size_kb": 64},
    remediation="Configure client_max_body_size in nginx; enforce Content-Length validation.",
)

UPLOAD_PROTECTION_RULE = DDoSDefenseRule(
    name="Upload Protection",
    technique=DDoSDefenseTechnique.UPLOAD_PROTECTION,
    description=(
        "Detect repeated large file uploads and enforce file-size "
        "limits and upload rate restrictions."
    ),
    attack_types=["Resource Exhaustion Upload"],
    action=DDoSDefenseAction.REJECTED,
    priority=24,
    thresholds={"max_upload_size_mb": 25, "max_uploads_per_minute": 5},
    remediation="Enforce file size limits, rate-limit uploads, and use virus/content scanning.",
)

WEBSOCKET_CONTROL_RULE = DDoSDefenseRule(
    name="WebSocket Connection Control",
    technique=DDoSDefenseTechnique.WEBSOCKET_CONNECTION_CTRL,
    description=(
        "Detect large numbers of WebSocket connection attempts and "
        "limit the number of sessions per client."
    ),
    attack_types=["WebSocket Connection Flood"],
    action=DDoSDefenseAction.CONNECTION_LIMITED,
    priority=20,
    thresholds={"max_ws_connections_per_ip": 5, "ws_handshake_timeout_seconds": 10},
    remediation="Limit WebSocket connections per origin/IP; enforce handshake timeouts.",
)

API_ABUSE_PROTECTION_RULE = DDoSDefenseRule(
    name="API Abuse Protection",
    technique=DDoSDefenseTechnique.API_ABUSE_PROTECTION,
    description=(
        "Detect repeated API requests intended to overload backend services. "
        "Simulate request throttling and temporary blocking."
    ),
    attack_types=["Recursive API Call Flood"],
    action=DDoSDefenseAction.THROTTLED,
    priority=19,
    thresholds={"max_api_calls_per_minute": 120, "recursive_depth_limit": 5},
    remediation="Implement API gateway rate limiting and circuit breakers.",
)

CACHING_PROTECTION_RULE = DDoSDefenseRule(
    name="Caching Protection",
    technique=DDoSDefenseTechnique.CACHING_PROTECTION,
    description=(
        "Detect attempts to bypass cache by randomizing query parameters. "
        "Enforce cache validation and reject suspicious requests."
    ),
    attack_types=["Cache Bypass Flood"],
    action=DDoSDefenseAction.BLOCKED,
    priority=17,
    thresholds={"max_unique_params_per_minute": 50},
    remediation="Normalize query parameters before cache lookup; ignore unknown params.",
)

DB_QUERY_PROTECTION_RULE = DDoSDefenseRule(
    name="Database Query Protection",
    technique=DDoSDefenseTechnique.DB_QUERY_PROTECTION,
    description=(
        "Detect repeated queries triggering expensive database operations. "
        "Simulate query throttling or request blocking."
    ),
    attack_types=["Database Query Amplification"],
    action=DDoSDefenseAction.THROTTLED,
    priority=23,
    thresholds={"max_heavy_queries_per_minute": 20, "query_timeout_ms": 3000},
    remediation="Add query timeouts, use prepared statements, and cache expensive queries.",
)

RATE_LIMIT_BYPASS_RULE = DDoSDefenseRule(
    name="Adaptive Rate Limit Bypass Detection",
    technique=DDoSDefenseTechnique.RATE_LIMIT_BYPASS_DETECT,
    description=(
        "Detect attempts to evade rate limits through rotating headers, "
        "changing user-agents, or varying request intervals. "
        "Simulate adaptive rate limiting."
    ),
    attack_types=["Rate Limit Bypass"],
    action=DDoSDefenseAction.BLOCKED,
    priority=26,
    thresholds={"fingerprint_similarity_threshold": 0.8},
    remediation="Implement fingerprint-based rate limiting beyond IP/session.",
)

LOGIN_BRUTEFORCE_RULE = DDoSDefenseRule(
    name="Login Brute Force Protection",
    technique=DDoSDefenseTechnique.RATE_LIMITING,
    description=(
        "Detect credential stuffing and brute-force login attempts. "
        "Lock accounts temporarily and enforce CAPTCHA after N failures."
    ),
    attack_types=["Login Brute Force Flood"],
    action=DDoSDefenseAction.RATE_LIMITED,
    priority=24,
    thresholds={"max_login_attempts": 5, "lockout_duration_minutes": 15},
    remediation="Implement account lockout, progressive delays, and CAPTCHA after failed attempts.",
)


# ── Collected rule set ────────────────────────────────────────────────────

ALL_DDOS_DEFENSE_RULES: List[DDoSDefenseRule] = sorted(
    [
        RATE_LIMITING_RULE,
        TRAFFIC_THROTTLING_RULE,
        IP_BLOCKING_RULE,
        CONNECTION_LIMITING_RULE,
        REQUEST_SIZE_VALIDATION_RULE,
        UPLOAD_PROTECTION_RULE,
        WEBSOCKET_CONTROL_RULE,
        API_ABUSE_PROTECTION_RULE,
        CACHING_PROTECTION_RULE,
        DB_QUERY_PROTECTION_RULE,
        RATE_LIMIT_BYPASS_RULE,
        LOGIN_BRUTEFORCE_RULE,
    ],
    key=lambda r: r.priority,
    reverse=True,
)
