"""
narrator_formatter.py — Human-readable commentary generator
------------------------------------------------------------
Transforms raw AttackEvent data into clear, descriptive narration
suitable for non-expert readers.  Each attack type has its own
narration strategy that explains what the attack does and how the
defense responds.

This module is pure-functional — it only reads event data and
produces strings.  It never mutates any external state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ── Attack type descriptions (educational) ────────────────────────────

_ATTACK_DESCRIPTIONS = {
    "SQL_INJECTION": (
        "SQL Injection attempts to manipulate database queries by injecting "
        "malicious SQL code into user-supplied input fields."
    ),
    "XSS": (
        "Cross-Site Scripting (XSS) injects malicious scripts into web pages "
        "viewed by other users, potentially stealing session data or credentials."
    ),
    "CORS": (
        "CORS Misconfiguration exploits overly permissive cross-origin resource "
        "sharing headers to access restricted data from unauthorized origins."
    ),
    "DDOS": (
        "Distributed Denial of Service (DDoS) overwhelms the target with a flood "
        "of requests, attempting to exhaust server resources and cause downtime."
    ),
}

# ── Defense technique descriptions (educational) ─────────────────────

_DEFENSE_DESCRIPTIONS = {
    "Input Validation": "Validates and sanitizes user input before it reaches the database.",
    "Parameterized Query": "Uses parameterized queries to prevent SQL code from being injected.",
    "Web Application Firewall": "A WAF rule intercepts and blocks known attack patterns.",
    "Query Pattern Detection": "Detects suspicious SQL patterns such as UNION SELECT or stacked queries.",
    "Privilege Escalation Guard": "Blocks attempts to elevate database privileges.",
    "Data Modification Guard": "Prevents unauthorized DELETE, DROP, or INSERT operations.",
    "Output Encoding": "Encodes output to prevent injected scripts from executing in the browser.",
    "Content Security Policy": "CSP headers restrict which scripts the browser is allowed to run.",
    "DOM Sanitization": "Sanitizes the DOM to remove injected script elements.",
    "Input Sanitization": "Strips dangerous characters and tags from user input.",
    "Origin Validation": "Validates the request Origin header against an allowlist of trusted domains.",
    "Header Hardening": "Enforces strict CORS headers to prevent unauthorized cross-origin access.",
    "Credential Restriction": "Disables Access-Control-Allow-Credentials for untrusted origins.",
    "Preflight Enforcement": "Requires proper preflight OPTIONS requests before allowing cross-origin calls.",
    "Rate Limiting": "Limits the number of requests per time window to prevent resource exhaustion.",
    "Connection Throttling": "Throttles connections from sources sending abnormally high traffic.",
    "Traffic Analysis": "Analyzes traffic patterns to distinguish legitimate users from attack traffic.",
    "IP Blacklisting": "Blocks IP addresses identified as sources of malicious traffic.",
    "Request Filtering": "Filters out requests matching known DDoS attack signatures.",
}


class NarratorFormatter:
    """Formats attack and defense events into human-readable narration."""

    # ── Main entry point ──────────────────────────────────────────────

    def narrate_attack_event(
        self,
        attack_type: str,
        target_url: str,
        findings_dicts: List[Dict[str, Any]],
        scan_log: Optional[list] = None,
        summary: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Generate narration lines for an attack event.

        Returns a list of commentary strings suitable for printing.
        """
        lines: List[str] = []
        label = _friendly_label(attack_type)

        # ── Opening ───────────────────────────────────────────────
        lines.append(f"AttackBot launches {label} scan against {target_url}.")

        description = _ATTACK_DESCRIPTIONS.get(attack_type)
        if description:
            lines.append(f"  ℹ {description}")

        # ── Dispatch to type-specific formatter ───────────────────
        if attack_type == "SQL_INJECTION":
            lines.extend(self._narrate_sql(scan_log, summary))
        elif attack_type == "XSS":
            lines.extend(self._narrate_xss(findings_dicts, summary))
        elif attack_type == "CORS":
            lines.extend(self._narrate_cors(findings_dicts, summary))
        elif attack_type == "DDOS":
            lines.extend(self._narrate_ddos(findings_dicts, summary))
        else:
            lines.extend(self._narrate_generic(findings_dicts, summary))

        return lines

    # ── SQL Injection narration ───────────────────────────────────────

    def _narrate_sql(
        self,
        scan_log: Optional[list],
        summary: Optional[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = []

        if not scan_log:
            lines.append("  No SQL injection scan log available.")
            return lines

        vuln_entries = [e for e in scan_log if getattr(e, "vulnerable", False)]
        safe_entries = [e for e in scan_log if not getattr(e, "vulnerable", False)]

        lines.append(
            f"  AttackBot tested {len(scan_log)} payloads — "
            f"{len(vuln_entries)} vulnerable, {len(safe_entries)} blocked."
        )

        for entry in vuln_entries[:5]:
            endpoint = getattr(entry, "endpoint", "?")
            payload = getattr(entry, "payload", "?")
            category = getattr(entry, "category", "SQL Injection")
            param = getattr(entry, "parameter", "?")
            lines.append(
                f"  AttackBot attempts {category} on {endpoint} "
                f"(param={param}) using payload: {_truncate(payload, 60)}"
            )
            lines.append(f"  Result: Endpoint is vulnerable!")

        for entry in safe_entries[:3]:
            endpoint = getattr(entry, "endpoint", "?")
            payload = getattr(entry, "payload", "?")
            lines.append(
                f"  AttackBot attempts injection on {endpoint} "
                f"with payload: {_truncate(payload, 60)}"
            )
            lines.append(f"  DefendBot blocks the attack — payload neutralized.")

        if len(vuln_entries) > 5:
            lines.append(f"  ... and {len(vuln_entries) - 5} more vulnerable endpoints.")

        return lines

    # ── XSS narration ─────────────────────────────────────────────────

    def _narrate_xss(
        self,
        findings: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = []

        if not findings:
            lines.append("  No XSS vulnerabilities detected. Target appears secure.")
            return lines

        total = len(findings)
        by_type: Dict[str, int] = {}
        for f in findings:
            xss_type = f.get("xss_type", "Unknown")
            by_type[xss_type] = by_type.get(xss_type, 0) + 1

        type_breakdown = ", ".join(f"{v} {k}" for k, v in by_type.items())
        lines.append(f"  AttackBot discovers {total} XSS vulnerabilities ({type_breakdown}).")

        for finding in findings[:5]:
            endpoint = finding.get("endpoint", "?")
            param = finding.get("parameter", "?")
            xss_type = finding.get("xss_type", "XSS")
            payload = finding.get("payload", "?")
            lines.append(
                f"  AttackBot injects {xss_type} payload into {endpoint} "
                f"(param={param}): {_truncate(payload, 50)}"
            )

        if total > 5:
            lines.append(f"  ... and {total - 5} more XSS findings.")

        return lines

    # ── CORS narration ────────────────────────────────────────────────

    def _narrate_cors(
        self,
        findings: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = []

        if not findings:
            lines.append("  No CORS misconfigurations detected. Headers look secure.")
            return lines

        total = len(findings)
        lines.append(f"  AttackBot discovers {total} CORS misconfiguration(s).")

        for finding in findings[:5]:
            issue = finding.get("issue_type", "misconfiguration")
            endpoint = finding.get("endpoint", "?")
            acao = finding.get("acao_header", "")
            lines.append(
                f"  AttackBot exploits {_friendly_cors_issue(issue)} on {endpoint}."
            )
            if acao:
                lines.append(
                    f"    Server responds with Access-Control-Allow-Origin: {acao}"
                )

        if total > 5:
            lines.append(f"  ... and {total - 5} more CORS issues.")

        return lines

    # ── DDoS narration ────────────────────────────────────────────────

    def _narrate_ddos(
        self,
        findings: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = []

        if not findings:
            lines.append("  No DDoS vulnerabilities detected. Server handles load well.")
            return lines

        total = len(findings)
        lines.append(f"  AttackBot identifies {total} DDoS vulnerability/ies.")

        for finding in findings[:5]:
            attack_type = finding.get("attack_type", "DDoS")
            endpoint = finding.get("endpoint", "?")
            severity = finding.get("severity", "unknown")
            lines.append(
                f"  AttackBot simulates {attack_type} flood on {endpoint} "
                f"(severity: {severity})."
            )

        if total > 5:
            lines.append(f"  ... and {total - 5} more DDoS findings.")

        return lines

    # ── Generic fallback ──────────────────────────────────────────────

    def _narrate_generic(
        self,
        findings: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = []
        total = len(findings)
        lines.append(f"  {total} finding(s) reported.")
        return lines

    # ── Defense narration (called after defense results are available)

    def narrate_defense_summary(
        self,
        attack_type: str,
        defense_summary: Dict[str, Any],
        battle_log: list,
    ) -> List[str]:
        """
        Generate narration for defense results.

        Parameters
        ----------
        attack_type : str
            E.g. "SQL_INJECTION", "XSS", etc.
        defense_summary : dict
            Summary dict from a DefendBot's get_summary().
        battle_log : list
            Battle log entries from a DefendBot's get_battle_log().
        """
        lines: List[str] = []
        label = _friendly_label(attack_type)

        mitigated = defense_summary.get(
            "total_mitigated",
            defense_summary.get("attacks_blocked",
            defense_summary.get("attacks_mitigated", 0)),
        )
        total = defense_summary.get(
            "total_evaluated",
            defense_summary.get("total_attacks_analyzed", 0),
        )
        rate = defense_summary.get("defense_rate", "N/A")

        lines.append(f"DefendBot activates {label} defense protocols.")
        lines.append(f"  DefendBot evaluates {total} attack(s) — mitigates {mitigated} ({rate}% defense rate).")

        # Narrate individual battle log entries (up to 8)
        for entry in battle_log[:8]:
            lines.extend(self._narrate_battle_entry(attack_type, entry))

        if len(battle_log) > 8:
            lines.append(f"  ... and {len(battle_log) - 8} more defense actions.")

        return lines

    def _narrate_battle_entry(self, attack_type: str, entry: Any) -> List[str]:
        """Narrate a single battle log entry."""
        lines: List[str] = []

        if isinstance(entry, dict):
            # Structured battle log (SQL / CORS)
            attack_info = entry.get("attack", {})
            defense_info = entry.get("defense", {})
            result = entry.get("result", "")

            a_type = attack_info.get("type", attack_info.get("issue_type", "Unknown"))
            endpoint = attack_info.get("endpoint", "?")
            technique = defense_info.get("technique", "?")
            action = defense_info.get("action", "?")
            explanation = defense_info.get("explanation", "")

            if "Mitigated" in result:
                lines.append(f"  DefendBot detects {a_type} at {endpoint}.")
                technique_desc = _DEFENSE_DESCRIPTIONS.get(technique, "")
                if technique_desc:
                    lines.append(f"    Defense: {technique}. {technique_desc}")
                else:
                    lines.append(f"    Defense activated: {technique}.")
                lines.append(f"    Result: Attack blocked ({action}).")
            else:
                lines.append(f"  {a_type} at {endpoint} — {action} (appears benign or unmatched).")

        elif isinstance(entry, str):
            # String battle log (XSS / DDoS)
            lines.append(f"  {entry}")

        return lines


# ── Helpers ───────────────────────────────────────────────────────────

_LABELS = {
    "SQL_INJECTION": "SQL Injection",
    "XSS": "Cross-Site Scripting (XSS)",
    "CORS": "CORS Misconfiguration",
    "DDOS": "DDoS",
}


def _friendly_label(attack_type: str) -> str:
    return _LABELS.get(attack_type, attack_type)


_CORS_ISSUES = {
    "wildcard_origin": "wildcard origin (*) reflection",
    "origin_reflection": "origin reflection vulnerability",
    "null_origin": "null origin acceptance",
    "subdomain_wildcard": "subdomain wildcard misconfiguration",
    "credentials_with_wildcard": "credentials allowed with wildcard origin",
    "insecure_method": "insecure HTTP method exposure",
}


def _friendly_cors_issue(issue_type: str) -> str:
    return _CORS_ISSUES.get(issue_type, issue_type)


def _truncate(text: str, max_len: int = 60) -> str:
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
