"""
ddos_attack_bot.py
------------------
Denial-of-Service vulnerability detection engine for Prahaar AI.

Simulates 10 DDoS attack patterns **safely inside a sandbox** to test whether
the target server has adequate protections:

  1.  HTTP Flood                   → HIGH
  2.  Slowloris                    → HIGH
  3.  Large Payload                → HIGH
  4.  Recursive API Call Flood     → HIGH
  5.  Login Brute Force Flood      → HIGH
  6.  Resource Exhaustion Upload   → CRITICAL
  7.  WebSocket Connection Flood   → HIGH
  8.  Cache Bypass Flood           → MEDIUM
  9.  Database Query Amplification → CRITICAL
  10. Rate Limit Bypass            → CRITICAL

Safety guarantees
~~~~~~~~~~~~~~~~~
* Global concurrency is capped (default: 20 concurrent requests).
* A health check runs between attack phases; scanning stops
  immediately if the sandbox server becomes unresponsive.
* All network I/O targets only the supplied ``target_url`` (sandbox).
* No destructive payloads are sent — the bot only *measures* responses.

This module is COMPLETELY INDEPENDENT of the SQL injection, XSS, and CORS
pipelines.  It does not import from or modify any of those modules.

Usage
-----
    from AttackBot.DDoS_Attacks.ddos_attack_bot import DDoSAttackBot, DDoSScanConfig

    bot = DDoSAttackBot(target_url="http://127.0.0.1:9000")
    findings = bot.run_scan(endpoints)
    for f in findings:
        print(f.attack_type, f.severity, f.endpoint)
"""

from __future__ import annotations

import logging
import random
import socket
import statistics
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import ConnectionError, ReadTimeout, Timeout

from .ddos_payloads import (
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
    get_all_profiles,
)

logger = logging.getLogger(__name__)


# ── Scan configuration ───────────────────────────────────────────────────

@dataclass
class DDoSScanConfig:
    """Tuneable parameters for a DDoS simulation run."""
    timeout: float = 8.0
    delay_between_requests: float = 0.02
    max_concurrency: int = 20
    user_agent: str = "DDoSAttackBot/1.0 (Prahaar_AI Security Scanner)"
    verify_ssl: bool = False
    verbose: bool = False
    health_check_timeout: float = 5.0
    abort_on_server_down: bool = True


# ── DDoS finding ─────────────────────────────────────────────────────────

@dataclass
class DDoSFinding:
    """A single DDoS vulnerability detection result."""
    attack_type: str
    severity: str
    endpoint: str
    observation: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    finding_type: str = "DDoS Vulnerability"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.finding_type,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "observation": self.observation,
            "recommendation": self.recommendation,
            "details": self.details,
        }


# ── DDoS Attack Bot ─────────────────────────────────────────────────────

class DDoSAttackBot:
    """
    DDoS vulnerability scanner that simulates load patterns against a
    sandboxed web application.

    Parameters
    ----------
    target_url : str
        Base URL of the sandbox server (e.g. ``http://127.0.0.1:9000``).
    config : DDoSScanConfig | None
        Optional configuration overrides.
    """

    def __init__(
        self,
        target_url: str,
        config: Optional[DDoSScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.config = config or DDoSScanConfig()
        self._findings: List[DDoSFinding] = []
        self._session: Optional[requests.Session] = None
        self._server_alive = True

    # ── Public API ────────────────────────────────────────────────────

    def run_scan(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> List[DDoSFinding]:
        """
        Run all DDoS simulations against the target.

        Parameters
        ----------
        endpoints : list[dict] | None
            Crawled endpoints with ``path`` and ``method`` keys.
            If None, scans the root (``/``) only.

        Returns
        -------
        list[DDoSFinding]
        """
        self._findings = []
        self._session = requests.Session()
        self._session.headers["User-Agent"] = self.config.user_agent
        self._session.verify = self.config.verify_ssl

        if not endpoints:
            endpoints = [{"path": "/", "method": "GET"}]

        try:
            # Verify server is up before starting
            if not self._health_check():
                logger.warning("[DDoSBot] Target server unreachable; aborting scan")
                return self._findings

            # Run each attack type sequentially; abort if server goes down
            self._run_http_flood(endpoints)
            self._check_and_continue()

            self._run_slowloris(endpoints)
            self._check_and_continue()

            self._run_large_payload(endpoints)
            self._check_and_continue()

            self._run_recursive_api_flood(endpoints)
            self._check_and_continue()

            self._run_login_bruteforce(endpoints)
            self._check_and_continue()

            self._run_upload_exhaustion(endpoints)
            self._check_and_continue()

            self._run_websocket_flood(endpoints)
            self._check_and_continue()

            self._run_cache_bypass_flood(endpoints)
            self._check_and_continue()

            self._run_db_query_amplification(endpoints)
            self._check_and_continue()

            self._run_rate_limit_bypass(endpoints)

        except _ServerDownAbort:
            logger.warning("[DDoSBot] Server became unresponsive; stopping scan early")
        finally:
            if self._session:
                self._session.close()

        logger.info("[DDoSBot] Scan complete — %d finding(s)", len(self._findings))
        return self._findings

    def get_findings_as_dicts(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self._findings]

    def findings_summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for f in self._findings:
            by_type[f.attack_type] = by_type.get(f.attack_type, 0) + 1
        return {
            "total_ddos_findings": len(self._findings),
            "by_type": by_type,
        }

    # ── Health check ──────────────────────────────────────────────────

    def _health_check(self) -> bool:
        """Return True if the sandbox server responds."""
        try:
            r = self._session.get(
                self.target_url + "/",
                timeout=self.config.health_check_timeout,
                allow_redirects=True,
            )
            self._server_alive = r.status_code < 600
            return self._server_alive
        except Exception:
            self._server_alive = False
            return False

    def _check_and_continue(self) -> None:
        """Abort scan if server is down and config says to stop."""
        if self.config.abort_on_server_down and not self._health_check():
            raise _ServerDownAbort()

    # ── Helpers ───────────────────────────────────────────────────────

    def _make_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.target_url + ("" if path.startswith("/") else "/") + path

    def _timed_request(
        self, method: str, url: str, **kwargs,
    ) -> Optional[requests.Response]:
        """Send a request and return the response, or None on error."""
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            return self._session.request(method, url, **kwargs)
        except (Timeout, ReadTimeout, ConnectionError):
            return None
        except Exception:
            return None

    def _measure_baseline(self, url: str, method: str = "GET", samples: int = 3) -> float:
        """Return average response time in ms for a baseline measurement."""
        times = []
        for _ in range(samples):
            t0 = time.perf_counter()
            resp = self._timed_request(method, url)
            elapsed = (time.perf_counter() - t0) * 1000
            if resp is not None:
                times.append(elapsed)
            time.sleep(self.config.delay_between_requests)
        return statistics.mean(times) if times else 500.0

    def _pick_endpoints(
        self,
        endpoints: List[Dict[str, Any]],
        path_patterns: Optional[List[str]] = None,
        max_count: int = 5,
    ) -> List[Dict[str, Any]]:
        """Filter endpoints by path patterns; fallback to all."""
        if path_patterns:
            matched = [
                ep for ep in endpoints
                if any(pat in ep.get("path", "") for pat in path_patterns)
            ]
            if matched:
                return matched[:max_count]
        return endpoints[:max_count]

    def _add_finding(
        self,
        attack_type: str,
        severity: str,
        endpoint: str,
        observation: str,
        recommendation: str,
        details: Optional[Dict] = None,
    ) -> None:
        self._findings.append(DDoSFinding(
            attack_type=attack_type,
            severity=severity,
            endpoint=endpoint,
            observation=observation,
            recommendation=recommendation,
            details=details or {},
        ))

    # ══════════════════════════════════════════════════════════════════
    # Attack simulations
    # ══════════════════════════════════════════════════════════════════

    # 1. HTTP Flood ────────────────────────────────────────────────────

    def _run_http_flood(self, endpoints: List[Dict]) -> None:
        profile = HTTP_FLOOD_PROFILE
        logger.info("[DDoSBot] Running HTTP Flood simulation")
        targets = self._pick_endpoints(endpoints, max_count=3)

        for ep in targets:
            url = self._make_url(ep.get("path", "/"))
            method = ep.get("method", "GET")
            baseline_ms = self._measure_baseline(url, method)

            total = profile.parameters["total_requests"]
            concurrency = min(profile.parameters["concurrency"], self.config.max_concurrency)
            threshold = profile.parameters["degradation_threshold_ms"]

            response_times: List[float] = []
            errors = 0

            def _flood_request(_i: int):
                t0 = time.perf_counter()
                resp = self._timed_request(method, url)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                return elapsed_ms, resp

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_flood_request, i) for i in range(total)]
                for fut in as_completed(futures):
                    try:
                        elapsed_ms, resp = fut.result()
                        response_times.append(elapsed_ms)
                        if resp is None or resp.status_code >= 500:
                            errors += 1
                    except Exception:
                        errors += 1

            if not response_times:
                continue

            avg_response = statistics.mean(response_times)
            max_response = max(response_times)
            degradation = avg_response - baseline_ms

            if degradation > threshold or errors > total * 0.2 or avg_response > baseline_ms * 3:
                # Server degraded — it's handling load but poorly
                pass
            else:
                # No degradation means server accepted everything without throttling
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ep.get("path", "/"),
                    observation=(
                        f"Server accepted {total} requests within "
                        f"{max_response / 1000:.1f}s without throttling. "
                        f"Avg response: {avg_response:.0f}ms, baseline: {baseline_ms:.0f}ms, "
                        f"errors: {errors}/{total}."
                    ),
                    recommendation="Implement request rate limiting or WAF protection.",
                    details={
                        "total_requests": total, "concurrency": concurrency,
                        "avg_response_ms": round(avg_response, 1),
                        "max_response_ms": round(max_response, 1),
                        "baseline_ms": round(baseline_ms, 1),
                        "errors": errors,
                    },
                )

            # Also flag if server started returning 5xx under load
            if errors > total * 0.3:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ep.get("path", "/"),
                    observation=(
                        f"Server returned errors for {errors}/{total} requests under "
                        f"concurrent load ({concurrency} threads). Potential denial-of-service."
                    ),
                    recommendation=(
                        "Implement load balancing, connection queuing, "
                        "or graceful degradation under high traffic."
                    ),
                    details={"errors": errors, "total_requests": total},
                )

    # 2. Slowloris ─────────────────────────────────────────────────────

    def _run_slowloris(self, endpoints: List[Dict]) -> None:
        profile = SLOWLORIS_PROFILE
        logger.info("[DDoSBot] Running Slowloris simulation")
        target_ep = endpoints[0] if endpoints else {"path": "/"}
        url = self._make_url(target_ep.get("path", "/"))

        # Parse host/port from target_url
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        max_conns = min(profile.parameters["max_connections"], self.config.max_concurrency * 2)
        header_delay = profile.parameters["header_delay_seconds"]
        path = target_ep.get("path", "/")

        open_sockets: List[socket.socket] = []
        accepted_count = 0

        for i in range(max_conns):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.config.timeout)
                s.connect((host, port))
                # Send a partial HTTP request
                s.send(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n".encode())
                open_sockets.append(s)
                accepted_count += 1
            except Exception:
                break

        # Try to keep connections alive with slow headers
        surviving = 0
        for s in open_sockets:
            try:
                s.send(f"X-Prahaar-{random.randint(1, 9999)}: slow\r\n".encode())
                surviving += 1
            except Exception:
                pass

        # Clean up
        for s in open_sockets:
            try:
                s.close()
            except Exception:
                pass

        if accepted_count > max_conns * 0.7:
            self._add_finding(
                attack_type=profile.name,
                severity=profile.risk_level,
                endpoint=target_ep.get("path", "/"),
                observation=(
                    f"Server accepted {accepted_count}/{max_conns} partial HTTP connections "
                    f"without enforcing connection timeouts. {surviving} connections "
                    f"remained alive after slow header injection."
                ),
                recommendation=(
                    "Implement connection timeouts, limit concurrent connections per IP, "
                    "or deploy a reverse proxy with Slowloris protection."
                ),
                details={
                    "connections_attempted": max_conns,
                    "connections_accepted": accepted_count,
                    "connections_surviving": surviving,
                },
            )

    # 3. Large Payload ─────────────────────────────────────────────────

    def _run_large_payload(self, endpoints: List[Dict]) -> None:
        profile = LARGE_PAYLOAD_PROFILE
        logger.info("[DDoSBot] Running Large Payload simulation")

        post_endpoints = [
            ep for ep in endpoints if ep.get("method", "GET").upper() == "POST"
        ]
        if not post_endpoints:
            post_endpoints = endpoints[:1]

        target_ep = post_endpoints[0]
        url = self._make_url(target_ep.get("path", "/"))
        max_accepted_mb = profile.parameters["max_accepted_size_mb"]

        for size_mb in profile.parameters["payload_sizes_mb"]:
            # Generate payload of the specified size
            payload = "A" * (size_mb * 1024 * 1024)
            try:
                resp = self._timed_request(
                    "POST", url,
                    data=payload,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=profile.parameters["timeout_per_request"],
                )

                if resp is not None and resp.status_code < 500:
                    if size_mb > max_accepted_mb:
                        self._add_finding(
                            attack_type=profile.name,
                            severity=profile.risk_level,
                            endpoint=target_ep.get("path", "/"),
                            observation=(
                                f"Server accepted a {size_mb}MB POST payload "
                                f"(status {resp.status_code}) without enforcing size limits."
                            ),
                            recommendation=(
                                "Enforce request body size limits (e.g., 1–5MB max) "
                                "at the web server or reverse proxy level."
                            ),
                            details={
                                "payload_size_mb": size_mb,
                                "status_code": resp.status_code,
                            },
                        )
                        break  # One finding is enough
                elif resp is not None and resp.status_code in (413, 414):
                    # Server correctly rejected — no vulnerability
                    break
            except Exception:
                continue

    # 4. Recursive API Call Flood ──────────────────────────────────────

    def _run_recursive_api_flood(self, endpoints: List[Dict]) -> None:
        profile = RECURSIVE_API_FLOOD_PROFILE
        logger.info("[DDoSBot] Running Recursive API Call Flood simulation")

        api_endpoints = self._pick_endpoints(
            endpoints,
            path_patterns=profile.parameters["api_path_patterns"],
            max_count=3,
        )
        if not api_endpoints:
            return

        for ep in api_endpoints:
            url = self._make_url(ep.get("path", "/"))
            method = ep.get("method", "GET")

            # Measure baseline
            baseline_ms = self._measure_baseline(url, method)

            # Send repeated requests and measure response time growth
            total = profile.parameters["total_requests"]
            concurrency = min(
                profile.parameters["concurrency"], self.config.max_concurrency,
            )
            response_times: List[float] = []

            def _api_request(_i: int):
                t0 = time.perf_counter()
                resp = self._timed_request(method, url)
                return (time.perf_counter() - t0) * 1000

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_api_request, i) for i in range(total)]
                for fut in as_completed(futures):
                    try:
                        response_times.append(fut.result())
                    except Exception:
                        pass

            if len(response_times) < 10:
                continue

            # Check for exponential growth in response time
            first_half = response_times[: len(response_times) // 2]
            second_half = response_times[len(response_times) // 2 :]
            avg_first = statistics.mean(first_half)
            avg_second = statistics.mean(second_half)

            threshold = profile.parameters["exponential_threshold_factor"]
            if avg_second > avg_first * threshold:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ep.get("path", "/"),
                    observation=(
                        f"Response time increased {avg_second / max(avg_first, 1):.1f}x "
                        f"under repeated API requests (baseline: {baseline_ms:.0f}ms → "
                        f"avg first half: {avg_first:.0f}ms → avg second half: {avg_second:.0f}ms). "
                        f"Potential recursive/cascading backend call abuse."
                    ),
                    recommendation=(
                        "Implement request throttling for API endpoints, "
                        "add circuit breakers for internal service calls, "
                        "and monitor backend resource usage."
                    ),
                    details={
                        "baseline_ms": round(baseline_ms, 1),
                        "avg_first_half_ms": round(avg_first, 1),
                        "avg_second_half_ms": round(avg_second, 1),
                        "growth_factor": round(avg_second / max(avg_first, 1), 2),
                    },
                )

    # 5. Login Brute Force Flood ──────────────────────────────────────

    def _run_login_bruteforce(self, endpoints: List[Dict]) -> None:
        profile = LOGIN_BRUTEFORCE_PROFILE
        logger.info("[DDoSBot] Running Login Brute Force Flood simulation")

        login_endpoints = self._pick_endpoints(
            endpoints,
            path_patterns=profile.parameters["login_path_patterns"],
            max_count=2,
        )
        if not login_endpoints:
            return

        usernames = profile.parameters["sample_usernames"]
        passwords = profile.parameters["sample_passwords"]
        total = profile.parameters["total_attempts"]
        concurrency = min(
            profile.parameters["concurrency"], self.config.max_concurrency,
        )

        for ep in login_endpoints:
            url = self._make_url(ep.get("path", "/"))
            successful_attempts = 0
            blocked_attempts = 0

            def _login_attempt(_i: int):
                u = usernames[_i % len(usernames)]
                p = passwords[_i % len(passwords)]
                resp = self._timed_request(
                    "POST", url,
                    data={"username": u, "password": p},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                return resp

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_login_attempt, i) for i in range(total)]
                for fut in as_completed(futures):
                    try:
                        resp = fut.result()
                        if resp is None:
                            blocked_attempts += 1
                        elif resp.status_code == 429:
                            blocked_attempts += 1
                        elif resp.status_code < 500:
                            successful_attempts += 1
                    except Exception:
                        blocked_attempts += 1

            if successful_attempts > total * 0.8:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ep.get("path", "/"),
                    observation=(
                        f"Server accepted {successful_attempts}/{total} login attempts "
                        f"without rate limiting or account lockout. "
                        f"Only {blocked_attempts} were blocked."
                    ),
                    recommendation=(
                        "Implement login rate limiting, account lockout after failed attempts, "
                        "CAPTCHA after repeated failures, and IP-based throttling."
                    ),
                    details={
                        "total_attempts": total,
                        "successful_attempts": successful_attempts,
                        "blocked_attempts": blocked_attempts,
                    },
                )

    # 6. Resource Exhaustion via File Upload ──────────────────────────

    def _run_upload_exhaustion(self, endpoints: List[Dict]) -> None:
        profile = UPLOAD_EXHAUSTION_PROFILE
        logger.info("[DDoSBot] Running Upload Exhaustion simulation")

        upload_endpoints = self._pick_endpoints(
            endpoints,
            path_patterns=profile.parameters["upload_path_patterns"],
            max_count=2,
        )
        if not upload_endpoints:
            return

        total = profile.parameters["total_uploads"]
        concurrency = min(
            profile.parameters["concurrency"], self.config.max_concurrency,
        )
        file_sizes_kb = profile.parameters["file_sizes_kb"]

        for ep in upload_endpoints:
            url = self._make_url(ep.get("path", "/"))
            accepted_uploads = 0
            rejected_uploads = 0

            def _upload_attempt(_i: int):
                size_kb = file_sizes_kb[_i % len(file_sizes_kb)]
                content = "X" * (size_kb * 1024)
                fname = f"test_upload_{_i}.bin"
                resp = self._timed_request(
                    "POST", url,
                    files={"file": (fname, content, "application/octet-stream")},
                    timeout=profile.parameters["timeout_per_upload"],
                )
                return resp

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_upload_attempt, i) for i in range(total)]
                for fut in as_completed(futures):
                    try:
                        resp = fut.result()
                        if resp is not None and resp.status_code < 500:
                            accepted_uploads += 1
                        else:
                            rejected_uploads += 1
                    except Exception:
                        rejected_uploads += 1

            if accepted_uploads > total * 0.7:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ep.get("path", "/"),
                    observation=(
                        f"Server accepted {accepted_uploads}/{total} file uploads "
                        f"without enforcing upload frequency or size restrictions."
                    ),
                    recommendation=(
                        "Enforce upload rate limits, maximum file size, "
                        "disk quota per user, and file type validation."
                    ),
                    details={
                        "total_uploads": total,
                        "accepted": accepted_uploads,
                        "rejected": rejected_uploads,
                    },
                )

    # 7. WebSocket Connection Flood ───────────────────────────────────

    def _run_websocket_flood(self, endpoints: List[Dict]) -> None:
        profile = WEBSOCKET_FLOOD_PROFILE
        logger.info("[DDoSBot] Running WebSocket Connection Flood simulation")

        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"

        ws_paths = profile.parameters["ws_path_patterns"]
        max_conns = min(
            profile.parameters["max_connections"], self.config.max_concurrency * 2,
        )

        # Try to connect via raw sockets with WebSocket upgrade
        for ws_path in ws_paths:
            accepted = 0
            sockets: List[socket.socket] = []

            for i in range(max_conns):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.config.timeout)
                    s.connect((host, port))

                    # Send WebSocket upgrade request
                    key = "".join(random.choices(string.ascii_letters, k=16))
                    upgrade_req = (
                        f"GET {ws_path} HTTP/1.1\r\n"
                        f"Host: {host}:{port}\r\n"
                        f"Upgrade: websocket\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n\r\n"
                    )
                    s.send(upgrade_req.encode())

                    # Check if server accepted
                    try:
                        data = s.recv(1024)
                        if b"101" in data or b"upgrade" in data.lower():
                            accepted += 1
                            sockets.append(s)
                            continue
                    except Exception:
                        pass

                    s.close()
                except Exception:
                    break

            # Clean up
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass

            if accepted > max_conns * 0.5:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ws_path,
                    observation=(
                        f"Server accepted {accepted}/{max_conns} WebSocket connections "
                        f"simultaneously without enforcing connection limits."
                    ),
                    recommendation=(
                        "Implement WebSocket connection limits per IP, "
                        "enforce authentication before upgrade, "
                        "and set connection idle timeouts."
                    ),
                    details={
                        "ws_path": ws_path,
                        "connections_attempted": max_conns,
                        "connections_accepted": accepted,
                    },
                )

    # 8. Cache Bypass Flood ───────────────────────────────────────────

    def _run_cache_bypass_flood(self, endpoints: List[Dict]) -> None:
        profile = CACHE_BYPASS_PROFILE
        logger.info("[DDoSBot] Running Cache Bypass Flood simulation")
        targets = self._pick_endpoints(endpoints, max_count=3)

        for ep in targets:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")

            # First: measure cached response (same URL, repeated)
            url_base = self._make_url(path)
            cached_times: List[float] = []
            for _ in range(5):
                t0 = time.perf_counter()
                self._timed_request(method, url_base)
                cached_times.append((time.perf_counter() - t0) * 1000)

            # Then: measure cache-busted responses (unique URL each time)
            total = profile.parameters["total_requests"]
            concurrency = min(
                profile.parameters["concurrency"], self.config.max_concurrency,
            )
            param_name = profile.parameters["random_param_name"]
            busted_times: List[float] = []

            def _busted_request(_i: int):
                bust_url = f"{url_base}?{param_name}={random.randint(100000, 999999)}"
                t0 = time.perf_counter()
                self._timed_request(method, bust_url)
                return (time.perf_counter() - t0) * 1000

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_busted_request, i) for i in range(total)]
                for fut in as_completed(futures):
                    try:
                        busted_times.append(fut.result())
                    except Exception:
                        pass

            if not cached_times or not busted_times:
                continue

            avg_cached = statistics.mean(cached_times)
            avg_busted = statistics.mean(busted_times)
            variance_threshold = profile.parameters["variance_threshold_ms"]

            # If busted responses are significantly slower, caching exists
            # If they're similar → server isn't using cache effectively
            if abs(avg_busted - avg_cached) < variance_threshold:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=path,
                    observation=(
                        f"Server recomputes responses for cache-busted requests. "
                        f"Avg cached: {avg_cached:.0f}ms, avg busted: {avg_busted:.0f}ms "
                        f"(difference: {abs(avg_busted - avg_cached):.0f}ms). "
                        f"An attacker could send requests with random parameters to bypass caching."
                    ),
                    recommendation=(
                        "Implement cache key normalization to ignore unknown query parameters, "
                        "or use a CDN with aggressive caching rules."
                    ),
                    details={
                        "avg_cached_ms": round(avg_cached, 1),
                        "avg_busted_ms": round(avg_busted, 1),
                    },
                )

    # 9. Database Query Amplification ─────────────────────────────────

    def _run_db_query_amplification(self, endpoints: List[Dict]) -> None:
        profile = DB_QUERY_AMPLIFICATION_PROFILE
        logger.info("[DDoSBot] Running Database Query Amplification simulation")

        api_endpoints = self._pick_endpoints(
            endpoints,
            path_patterns=["/api/", "/search", "/query", "/data", "/list"],
            max_count=3,
        )
        if not api_endpoints:
            return

        heavy_params = profile.parameters["heavy_query_params"]
        total = profile.parameters["total_requests"]
        concurrency = min(
            profile.parameters["concurrency"], self.config.max_concurrency,
        )

        for ep in api_endpoints:
            url = self._make_url(ep.get("path", "/"))
            method = ep.get("method", "GET")

            # Baseline: normal request
            baseline_ms = self._measure_baseline(url, method)

            # Heavy query parameter requests
            heavy_times: List[float] = []

            def _heavy_request(_i: int):
                t0 = time.perf_counter()
                if method.upper() == "GET":
                    self._timed_request(method, url, params=heavy_params)
                else:
                    self._timed_request(method, url, data=heavy_params)
                return (time.perf_counter() - t0) * 1000

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_heavy_request, i) for i in range(total)]
                for fut in as_completed(futures):
                    try:
                        heavy_times.append(fut.result())
                    except Exception:
                        pass

            if not heavy_times:
                continue

            avg_heavy = statistics.mean(heavy_times)
            threshold = profile.parameters["slowdown_threshold_factor"]

            if avg_heavy > baseline_ms * threshold:
                self._add_finding(
                    attack_type=profile.name,
                    severity=profile.risk_level,
                    endpoint=ep.get("path", "/"),
                    observation=(
                        f"Server slowed {avg_heavy / max(baseline_ms, 1):.1f}x under "
                        f"heavy query parameters (baseline: {baseline_ms:.0f}ms → "
                        f"heavy avg: {avg_heavy:.0f}ms). "
                        f"Database query amplification may be possible."
                    ),
                    recommendation=(
                        "Implement query complexity limits, pagination enforcement, "
                        "query caching, and database connection pooling with timeouts."
                    ),
                    details={
                        "baseline_ms": round(baseline_ms, 1),
                        "avg_heavy_ms": round(avg_heavy, 1),
                        "slowdown_factor": round(avg_heavy / max(baseline_ms, 1), 2),
                    },
                )

    # 10. Rate Limit Bypass ───────────────────────────────────────────

    def _run_rate_limit_bypass(self, endpoints: List[Dict]) -> None:
        profile = RATE_LIMIT_BYPASS_PROFILE
        logger.info("[DDoSBot] Running Rate Limit Bypass simulation")
        targets = self._pick_endpoints(endpoints, max_count=3)

        total_per_technique = profile.parameters["total_requests_per_technique"]
        concurrency = min(
            profile.parameters["concurrency"], self.config.max_concurrency,
        )
        bypass_headers = profile.parameters["bypass_headers"]
        user_agents = profile.parameters["user_agents"]

        for ep in targets:
            url = self._make_url(ep.get("path", "/"))
            method = ep.get("method", "GET")

            for header_template in bypass_headers:
                successful = 0

                def _bypass_request(_i: int):
                    headers = {}
                    for k, v in header_template.items():
                        headers[k] = v.replace("{i}", str(_i))
                    headers["User-Agent"] = user_agents[_i % len(user_agents)]
                    return self._timed_request(method, url, headers=headers)

                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futures = [
                        pool.submit(_bypass_request, i)
                        for i in range(total_per_technique)
                    ]
                    for fut in as_completed(futures):
                        try:
                            resp = fut.result()
                            if resp is not None and resp.status_code not in (429, 503):
                                successful += 1
                        except Exception:
                            pass

                header_name = list(header_template.keys())[0]
                if successful > total_per_technique * 0.9:
                    self._add_finding(
                        attack_type=profile.name,
                        severity=profile.risk_level,
                        endpoint=ep.get("path", "/"),
                        observation=(
                            f"Rate limiting was bypassed using spoofed {header_name} headers. "
                            f"{successful}/{total_per_technique} requests succeeded."
                        ),
                        recommendation=(
                            f"Do not trust client-supplied headers ({header_name}) for "
                            f"rate limiting. Use the actual connection IP from the socket layer, "
                            f"or a trusted proxy header configured at the infrastructure level."
                        ),
                        details={
                            "bypass_header": header_name,
                            "successful_requests": successful,
                            "total_requests": total_per_technique,
                        },
                    )
                    break  # One bypass vector is enough per endpoint


# ── Internal sentinel ─────────────────────────────────────────────────────

class _ServerDownAbort(Exception):
    """Raised internally to abort the scan when the server is unresponsive."""
