"""
ddos_defense_response.py
------------------------
Evaluation engine that matches DDoSAttackEvents against defense rules
and produces DDoSDefenseVerdicts with technique-specific explanations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .ddos_defense_monitor import DDoSAttackEvent
from .ddos_defense_rules import (
    ALL_DDOS_DEFENSE_RULES,
    DDoSDefenseAction,
    DDoSDefenseRule,
    DDoSDefenseTechnique,
    DDoSDefenseVerdict,
)


# ── Technique-specific explanation templates ──────────────────────────────

_TECHNIQUE_EXPLANATIONS: Dict[DDoSDefenseTechnique, str] = {
    DDoSDefenseTechnique.RATE_LIMITING: (
        "Abnormal request rate detected. Rate limiting activated — "
        "requests exceeding {max_rps} req/s per IP are rejected with HTTP 429."
    ),
    DDoSDefenseTechnique.TRAFFIC_THROTTLING: (
        "Traffic spike detected ({factor}x above baseline). "
        "Request processing delayed by {delay}ms to protect the server."
    ),
    DDoSDefenseTechnique.IP_BLOCKING: (
        "Repeated malicious behaviour detected from source IP. "
        "IP temporarily blocked for {block_min} minutes."
    ),
    DDoSDefenseTechnique.CONNECTION_LIMITING: (
        "Excessive open connections detected. "
        "Concurrent connection limit enforced: max {max_conn} per IP, "
        "idle timeout {timeout}s."
    ),
    DDoSDefenseTechnique.REQUEST_SIZE_VALIDATION: (
        "Abnormally large request payload detected. "
        "Requests exceeding {max_size}MB rejected (HTTP 413)."
    ),
    DDoSDefenseTechnique.UPLOAD_PROTECTION: (
        "Repeated large file upload detected. "
        "Upload size limit ({max_upload}MB) and rate limit "
        "({max_rate}/min) enforced."
    ),
    DDoSDefenseTechnique.WEBSOCKET_CONNECTION_CTRL: (
        "WebSocket connection flood detected. "
        "Max {max_ws} WebSocket sessions per client enforced; "
        "handshake timeout {ws_timeout}s."
    ),
    DDoSDefenseTechnique.API_ABUSE_PROTECTION: (
        "Recursive/excessive API calls detected. "
        "API request throttling activated: max {max_api}/min. "
        "Circuit breaker engaged."
    ),
    DDoSDefenseTechnique.CACHING_PROTECTION: (
        "Cache bypass attempt detected (randomized query parameters). "
        "Query parameters normalized before cache lookup; "
        "suspicious requests blocked."
    ),
    DDoSDefenseTechnique.DB_QUERY_PROTECTION: (
        "Expensive database query pattern detected. "
        "Query throttled: max {max_queries}/min, "
        "query timeout {query_timeout}ms enforced."
    ),
    DDoSDefenseTechnique.RATE_LIMIT_BYPASS_DETECT: (
        "Rate limit evasion attempt detected (rotating headers/user-agents). "
        "Adaptive fingerprint-based rate limiting engaged."
    ),
}


def _format_explanation(technique: DDoSDefenseTechnique, rule: DDoSDefenseRule) -> str:
    """Fill explanation template with rule thresholds."""
    tpl = _TECHNIQUE_EXPLANATIONS.get(technique, "Defense applied: " + rule.description)
    t = rule.thresholds
    return tpl.format(
        max_rps=t.get("max_requests_per_second", 50),
        factor=t.get("spike_detection_factor", 3.0),
        delay=t.get("throttle_delay_ms", 500),
        block_min=t.get("block_duration_minutes", 15),
        max_conn=t.get("max_connections_per_ip", 10),
        timeout=t.get("idle_timeout_seconds", 30),
        max_size=t.get("max_body_size_mb", 10),
        max_upload=t.get("max_upload_size_mb", 25),
        max_rate=t.get("max_uploads_per_minute", 5),
        max_ws=t.get("max_ws_connections_per_ip", 5),
        ws_timeout=t.get("ws_handshake_timeout_seconds", 10),
        max_api=t.get("max_api_calls_per_minute", 120),
        max_queries=t.get("max_heavy_queries_per_minute", 20),
        query_timeout=t.get("query_timeout_ms", 3000),
    )


# ── Defense engine ────────────────────────────────────────────────────────

class DDoSDefenseEngine:
    """Evaluates DDoSAttackEvents against defense rules and produces verdicts."""

    def __init__(self, rules: Optional[List[DDoSDefenseRule]] = None) -> None:
        self._rules = rules or list(ALL_DDOS_DEFENSE_RULES)
        self._verdicts: List[DDoSDefenseVerdict] = []

    def evaluate(self, event: DDoSAttackEvent) -> DDoSDefenseVerdict:
        matched_rules: List[DDoSDefenseRule] = []

        for rule in self._rules:
            if event.attack_type in rule.attack_types:
                matched_rules.append(rule)

        if matched_rules:
            best = max(matched_rules, key=lambda r: r.priority)
            technique = best.technique
            explanation = _format_explanation(technique, best)

            verdict = DDoSDefenseVerdict(
                attack_type=event.attack_type,
                severity=event.severity,
                endpoint=event.endpoint,
                observation=event.observation,
                recommendation=event.recommendation,
                details=event.details,
                triggered_rules=matched_rules,
                action=best.action,
                technique=technique,
                explanation=explanation,
            )
        else:
            verdict = DDoSDefenseVerdict(
                attack_type=event.attack_type,
                severity=event.severity,
                endpoint=event.endpoint,
                observation=event.observation,
                recommendation=event.recommendation,
                details=event.details,
                action=DDoSDefenseAction.ALLOWED,
                explanation="No matching defense rule. Manual review recommended.",
            )

        self._verdicts.append(verdict)
        return verdict

    @property
    def verdicts(self) -> List[DDoSDefenseVerdict]:
        return list(self._verdicts)

    def get_verdicts_as_dicts(self) -> List[Dict[str, Any]]:
        return [v.to_dict() for v in self._verdicts]

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._verdicts)
        mitigated = sum(1 for v in self._verdicts if v.mitigated)
        by_technique: Dict[str, int] = {}
        by_attack_type: Dict[str, int] = {}
        by_action: Dict[str, int] = {}

        for v in self._verdicts:
            if v.technique:
                t = v.technique.value
                by_technique[t] = by_technique.get(t, 0) + 1
            a_type = v.attack_type
            by_attack_type[a_type] = by_attack_type.get(a_type, 0) + 1
            act = v.action.value
            by_action[act] = by_action.get(act, 0) + 1

        return {
            "total_evaluated": total,
            "total_mitigated": mitigated,
            "total_allowed": total - mitigated,
            "defense_rate": round(mitigated / total * 100, 1) if total else 0.0,
            "by_technique": by_technique,
            "by_attack_type": by_attack_type,
            "by_action": by_action,
        }

    def reset(self) -> None:
        self._verdicts.clear()
