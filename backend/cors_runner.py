"""
cors_runner.py  –  CORS Integration Module
--------------------------------------------
Wrapper that bridges the Crawler output and the CORSAttackBot.

Performance optimizations:
  • asyncio.to_thread for parallel endpoint chunk scanning  (Opt 1, 2)
  • Async latency measurement for adaptive timeout          (Opt 10)
  • Endpoint deduplication before scanning                   (Opt 6)
  • Higher concurrency (up to cpu*4, max 16)                (Opt 14)
  • Each bot instance has its own requests.Session           (Opt 4)

Does NOT modify any attack detection logic.
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

from AttackBot.CORS_Attacks.cors_attack_bot import CORSAttackBot, CORSScanConfig, CORSFinding
from async_engine import measure_latency_async, run_sync

logger = logging.getLogger(__name__)


# ── Helper utilities ──────────────────────────────────────────────────────

def _split_list(items: list, n: int) -> List[list]:
    if n <= 1 or not items:
        return [items] if items else []
    k, m = divmod(len(items), n)
    chunks = [items[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]
    return [c for c in chunks if c]


def _crawled_to_cors_ep(crawled) -> Dict[str, Any]:
    if isinstance(crawled, dict):
        return {
            "path":   crawled.get("path", "/"),
            "method": crawled.get("method", "GET"),
        }
    return {
        "path":   getattr(crawled, "path", "/"),
        "method": getattr(crawled, "method", "GET"),
    }


def _dedup_cors_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for ep in endpoints:
        key = (ep["path"], ep["method"])
        if key not in seen:
            seen.add(key)
            out.append(ep)
    out.sort(key=lambda e: (e["path"], e["method"]))
    return out


# ── CORS Runner ───────────────────────────────────────────────────────────

class CORSRunner:
    """Integration layer around CORSAttackBot with async parallel scanning."""

    def __init__(
        self,
        target_url: str,
        config: Optional[CORSScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.config = config or CORSScanConfig(
            verbose=False,
            timeout=8.0,
            delay_between_requests=0.05,
        )
        self._findings: List[CORSFinding] = []

    # ── Public API (sync) ─────────────────────────────────────────────

    def run(self, crawled_endpoints: Optional[List[Any]] = None) -> Dict[str, Any]:
        return run_sync(self.run_async(crawled_endpoints))

    # ── Async implementation ──────────────────────────────────────────

    async def run_async(
        self, crawled_endpoints: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        try:
            cors_endpoints: Optional[List[Dict[str, Any]]] = None
            if crawled_endpoints:
                cors_endpoints = [_crawled_to_cors_ep(ep) for ep in crawled_endpoints]
                cors_endpoints = _dedup_cors_endpoints(cors_endpoints)

            endpoint_count = len(cors_endpoints) if cors_endpoints else 0
            logger.info("[CORSRunner] Starting CORS scan on %s — %d endpoints",
                        self.target_url, endpoint_count)

            if not cors_endpoints or endpoint_count == 0:
                bot = CORSAttackBot(target_url=self.target_url, config=self.config)
                self._findings = await asyncio.to_thread(bot.run_scan, None)
                return self._build_result(bot)

            # Adaptive timeout
            adapted_config = await self._adapt_timeout_async()

            # Parallel endpoint scanning
            n_workers = min(endpoint_count, max(2, (os.cpu_count() or 2) * 4), 16)
            if endpoint_count <= 2:
                n_workers = 1

            logger.info("[CORSRunner] Scanning %d endpoints with %d worker(s)",
                        endpoint_count, n_workers)

            all_findings: List[CORSFinding] = []
            all_dicts: List[Dict[str, Any]] = []

            def _scan_chunk(chunk: List[Dict[str, Any]]):
                bot = CORSAttackBot(target_url=self.target_url, config=adapted_config)
                findings = bot.run_scan(endpoints=chunk)
                return findings, bot.get_findings_as_dicts()

            if n_workers <= 1:
                findings, dicts = await asyncio.to_thread(_scan_chunk, cors_endpoints)
                all_findings.extend(findings)
                all_dicts.extend(dicts)
            else:
                chunks = _split_list(cors_endpoints, n_workers)
                tasks = [asyncio.to_thread(_scan_chunk, c) for c in chunks]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, res in enumerate(results):
                    if isinstance(res, Exception):
                        logger.warning("[CORSRunner] Chunk %d error: %s", i, res)
                    else:
                        all_findings.extend(res[0])
                        all_dicts.extend(res[1])

            self._findings = all_findings

            by_type: Dict[str, int] = Counter()
            for f in all_findings:
                by_type[f.finding_type] += 1
            summary = {"total_cors_findings": len(all_findings), "by_type": dict(by_type)}

            logger.info("[CORSRunner] CORS scan complete — %d finding(s)", len(all_findings))

            return {
                "success": True, "findings": all_findings,
                "findings_dicts": all_dicts, "summary": summary, "error": None,
            }

        except Exception as exc:
            logger.exception("[CORSRunner] CORS scan failed")
            return {
                "success": False, "findings": [], "findings_dicts": [],
                "summary": {"total_cors_findings": 0}, "error": str(exc),
            }

    # ── Accessors ─────────────────────────────────────────────────────

    @property
    def findings(self) -> List[CORSFinding]:
        return self._findings

    # ── Internal helpers ──────────────────────────────────────────────

    def _build_result(self, bot: CORSAttackBot) -> Dict[str, Any]:
        summary = bot.findings_summary()
        logger.info("[CORSRunner] CORS scan complete — %d finding(s)",
                    summary["total_cors_findings"])
        return {
            "success": True, "findings": self._findings,
            "findings_dicts": bot.get_findings_as_dicts(),
            "summary": summary, "error": None,
        }

    async def _adapt_timeout_async(self) -> CORSScanConfig:
        measured = await measure_latency_async(self.target_url)
        timeout = self.config.timeout
        if measured is not None:
            timeout = min(max(measured * 5, 3.0), 15.0)
            logger.info("[CORSRunner] Adaptive timeout: %.1fs (latency: %.3fs)",
                        timeout, measured)
        return CORSScanConfig(
            timeout=timeout,
            delay_between_requests=self.config.delay_between_requests,
            verbose=False,
        )
