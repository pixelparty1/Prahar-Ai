"""
ddos_runner.py  –  DDoS Integration Module
--------------------------------------------
Wrapper that bridges the Crawler output and the DDoSAttackBot.

Performance optimizations:
  • asyncio.to_thread for parallel endpoint chunk scanning
  • Async latency measurement for adaptive timeout
  • Endpoint deduplication before scanning
  • Higher concurrency (up to cpu*4, max 16)
  • Each bot instance has its own requests.Session

Does NOT modify any existing attack detection logic.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional

_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from AttackBot.DDoS_Attacks.ddos_attack_bot import DDoSAttackBot, DDoSScanConfig, DDoSFinding
from async_engine import measure_latency_async, run_sync

logger = logging.getLogger(__name__)


# ── Helper utilities ──────────────────────────────────────────────────────

def _split_list(items: list, n: int) -> List[list]:
    if n <= 1 or not items:
        return [items] if items else []
    k, m = divmod(len(items), n)
    chunks = [items[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]
    return [c for c in chunks if c]


def _crawled_to_ddos_ep(crawled) -> Dict[str, Any]:
    if isinstance(crawled, dict):
        return {
            "path":   crawled.get("path", "/"),
            "method": crawled.get("method", "GET"),
        }
    return {
        "path":   getattr(crawled, "path", "/"),
        "method": getattr(crawled, "method", "GET"),
    }


def _dedup_ddos_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for ep in endpoints:
        key = (ep["path"], ep["method"])
        if key not in seen:
            seen.add(key)
            out.append(ep)
    out.sort(key=lambda e: (e["path"], e["method"]))
    return out


# ── DDoS Runner ───────────────────────────────────────────────────────────

class DDoSRunner:
    """Integration layer around DDoSAttackBot with async parallel scanning."""

    def __init__(
        self,
        target_url: str,
        config: Optional[DDoSScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.config = config or DDoSScanConfig(
            verbose=False,
            timeout=8.0,
            delay_between_requests=0.05,
        )
        self._findings: List[DDoSFinding] = []

    # ── Public API (sync) ─────────────────────────────────────────────

    def run(self, crawled_endpoints: Optional[List[Any]] = None) -> Dict[str, Any]:
        return run_sync(self.run_async(crawled_endpoints))

    # ── Async implementation ──────────────────────────────────────────

    async def run_async(
        self, crawled_endpoints: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        try:
            ddos_endpoints: Optional[List[Dict[str, Any]]] = None
            if crawled_endpoints:
                ddos_endpoints = [_crawled_to_ddos_ep(ep) for ep in crawled_endpoints]
                ddos_endpoints = _dedup_ddos_endpoints(ddos_endpoints)

            endpoint_count = len(ddos_endpoints) if ddos_endpoints else 0
            logger.info("[DDoSRunner] Starting DDoS scan on %s — %d endpoints",
                        self.target_url, endpoint_count)

            if not ddos_endpoints or endpoint_count == 0:
                bot = DDoSAttackBot(target_url=self.target_url, config=self.config)
                self._findings = await asyncio.to_thread(bot.run_scan, None)
                return self._build_result(bot)

            # Adaptive timeout
            adapted_config = await self._adapt_timeout_async()

            # DDoS scans are inherently sequential (each attack type tests
            # the server from scratch) so we run a single bot instance
            # across all endpoints rather than splitting into chunks.
            logger.info("[DDoSRunner] Scanning %d endpoints with DDoS bot",
                        endpoint_count)

            def _scan_all():
                bot = DDoSAttackBot(target_url=self.target_url, config=adapted_config)
                findings = bot.run_scan(endpoints=ddos_endpoints)
                return findings, bot.get_findings_as_dicts()

            all_findings, all_dicts = await asyncio.to_thread(_scan_all)
            self._findings = all_findings

            by_type: Dict[str, int] = Counter()
            for f in all_findings:
                by_type[f.attack_type] += 1
            summary = {"total_ddos_findings": len(all_findings), "by_type": dict(by_type)}

            logger.info("[DDoSRunner] DDoS scan complete — %d finding(s)", len(all_findings))

            return {
                "success": True, "findings": all_findings,
                "findings_dicts": all_dicts, "summary": summary, "error": None,
            }

        except Exception as exc:
            logger.exception("[DDoSRunner] DDoS scan failed")
            return {
                "success": False, "findings": [], "findings_dicts": [],
                "summary": {"total_ddos_findings": 0}, "error": str(exc),
            }

    # ── Accessors ─────────────────────────────────────────────────────

    @property
    def findings(self) -> List[DDoSFinding]:
        return self._findings

    # ── Internal helpers ──────────────────────────────────────────────

    def _build_result(self, bot: DDoSAttackBot) -> Dict[str, Any]:
        summary = bot.findings_summary()
        logger.info("[DDoSRunner] DDoS scan complete — %d finding(s)",
                    summary["total_ddos_findings"])
        return {
            "success": True, "findings": self._findings,
            "findings_dicts": bot.get_findings_as_dicts(),
            "summary": summary, "error": None,
        }

    async def _adapt_timeout_async(self) -> DDoSScanConfig:
        measured = await measure_latency_async(self.target_url)
        timeout = self.config.timeout
        if measured is not None:
            timeout = min(max(measured * 5, 3.0), 15.0)
            logger.info("[DDoSRunner] Adaptive timeout: %.1fs (latency: %.3fs)",
                        timeout, measured)
        return DDoSScanConfig(
            timeout=timeout,
            delay_between_requests=self.config.delay_between_requests,
            verbose=False,
        )
