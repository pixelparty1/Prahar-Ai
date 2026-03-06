"""
ddos_payloads.py
----------------
Central repository of DDoS simulation parameters organized by attack type.
All payloads are for **detection only** — the bot simulates load patterns
to test whether the target has proper rate limiting, throttling, and
resource protection. It does NOT cause real damage.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DDoSAttackProfile:
    """Configuration for a single DDoS simulation type."""
    name: str
    description: str
    risk_level: str
    parameters: Dict = field(default_factory=dict)


# ── HTTP Flood ────────────────────────────────────────────────────────────

HTTP_FLOOD_PROFILE = DDoSAttackProfile(
    name="HTTP Flood",
    description="Send a large number of concurrent HTTP GET/POST requests to discovered endpoints.",
    risk_level="HIGH",
    parameters={
        "total_requests": 200,
        "concurrency": 20,
        "methods": ["GET", "POST"],
        "timeout_per_request": 5.0,
        "degradation_threshold_ms": 500,
    },
)

# ── Slowloris ─────────────────────────────────────────────────────────────

SLOWLORIS_PROFILE = DDoSAttackProfile(
    name="Slowloris",
    description="Open many connections but send headers slowly to test connection timeout protection.",
    risk_level="HIGH",
    parameters={
        "max_connections": 50,
        "header_delay_seconds": 2.0,
        "total_duration_seconds": 15,
        "partial_header": "X-Prahaar-Slow: ",
        "timeout_detection_threshold": 30,
    },
)

# ── Large Payload ─────────────────────────────────────────────────────────

LARGE_PAYLOAD_PROFILE = DDoSAttackProfile(
    name="Large Payload",
    description="Send unusually large POST payloads (10MB–50MB) to endpoints.",
    risk_level="HIGH",
    parameters={
        "payload_sizes_mb": [1, 5, 10, 25, 50],
        "timeout_per_request": 15.0,
        "max_accepted_size_mb": 5,
    },
)

# ── Recursive API Call Flood ──────────────────────────────────────────────

RECURSIVE_API_FLOOD_PROFILE = DDoSAttackProfile(
    name="Recursive API Call Flood",
    description="Send repeated requests to endpoints that may trigger cascading backend calls.",
    risk_level="HIGH",
    parameters={
        "total_requests": 100,
        "concurrency": 10,
        "api_path_patterns": ["/api/", "/graphql", "/webhook", "/callback"],
        "exponential_threshold_factor": 3.0,
    },
)

# ── Login Brute Force Flood ──────────────────────────────────────────────

LOGIN_BRUTEFORCE_PROFILE = DDoSAttackProfile(
    name="Login Brute Force Flood",
    description="Send repeated login attempts with different credentials to test rate limiting.",
    risk_level="HIGH",
    parameters={
        "total_attempts": 100,
        "concurrency": 10,
        "login_path_patterns": ["/login", "/signin", "/auth", "/api/login", "/api/auth"],
        "sample_usernames": ["admin", "test", "user", "root", "guest"],
        "sample_passwords": ["password", "123456", "admin", "test", "letmein"],
    },
)

# ── Resource Exhaustion via File Upload ──────────────────────────────────

UPLOAD_EXHAUSTION_PROFILE = DDoSAttackProfile(
    name="Resource Exhaustion via File Upload",
    description="Attempt repeated file uploads to test upload rate and size limits.",
    risk_level="CRITICAL",
    parameters={
        "total_uploads": 30,
        "concurrency": 5,
        "upload_path_patterns": ["/upload", "/api/upload", "/files", "/api/files"],
        "file_sizes_kb": [100, 500, 1024, 5120],
        "timeout_per_upload": 15.0,
    },
)

# ── WebSocket Connection Flood ───────────────────────────────────────────

WEBSOCKET_FLOOD_PROFILE = DDoSAttackProfile(
    name="WebSocket Connection Flood",
    description="Open many WebSocket connections simultaneously to test connection limits.",
    risk_level="HIGH",
    parameters={
        "max_connections": 50,
        "ws_path_patterns": ["/ws", "/socket", "/websocket", "/socket.io/"],
        "hold_duration_seconds": 10,
    },
)

# ── Cache Bypass Flood ───────────────────────────────────────────────────

CACHE_BYPASS_PROFILE = DDoSAttackProfile(
    name="Cache Bypass Flood",
    description="Send requests with random query parameters to bypass caching.",
    risk_level="MEDIUM",
    parameters={
        "total_requests": 100,
        "concurrency": 15,
        "random_param_name": "cachebust",
        "variance_threshold_ms": 100,
    },
)

# ── Database Query Amplification ─────────────────────────────────────────

DB_QUERY_AMPLIFICATION_PROFILE = DDoSAttackProfile(
    name="Database Query Amplification",
    description="Send requests that trigger expensive database queries repeatedly.",
    risk_level="CRITICAL",
    parameters={
        "total_requests": 50,
        "concurrency": 10,
        "heavy_query_params": {
            "sort": "created_at",
            "order": "desc",
            "limit": "999999",
            "offset": "0",
            "search": "a",
            "filter": "*",
        },
        "slowdown_threshold_factor": 3.0,
    },
)

# ── Rate Limit Bypass Test ───────────────────────────────────────────────

RATE_LIMIT_BYPASS_PROFILE = DDoSAttackProfile(
    name="Rate Limit Bypass",
    description="Attempt to bypass rate limiting using headers, user agents, and timing.",
    risk_level="CRITICAL",
    parameters={
        "total_requests_per_technique": 50,
        "concurrency": 10,
        "bypass_headers": [
            {"X-Forwarded-For": "10.0.0.{i}"},
            {"X-Real-IP": "192.168.1.{i}"},
            {"X-Originating-IP": "172.16.0.{i}"},
            {"X-Client-IP": "10.10.10.{i}"},
            {"CF-Connecting-IP": "203.0.113.{i}"},
        ],
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "curl/7.88.1",
            "PrahaarAI-Scanner/1.0",
        ],
    },
)


# ── Aggregated payloads ──────────────────────────────────────────────────

ALL_DDOS_PROFILES: List[DDoSAttackProfile] = [
    HTTP_FLOOD_PROFILE,
    SLOWLORIS_PROFILE,
    LARGE_PAYLOAD_PROFILE,
    RECURSIVE_API_FLOOD_PROFILE,
    LOGIN_BRUTEFORCE_PROFILE,
    UPLOAD_EXHAUSTION_PROFILE,
    WEBSOCKET_FLOOD_PROFILE,
    CACHE_BYPASS_PROFILE,
    DB_QUERY_AMPLIFICATION_PROFILE,
    RATE_LIMIT_BYPASS_PROFILE,
]


def get_all_profiles() -> List[DDoSAttackProfile]:
    """Return every DDoS attack profile."""
    return list(ALL_DDOS_PROFILES)
