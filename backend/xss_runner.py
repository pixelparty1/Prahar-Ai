"""
xss_runner.py  –  XSS Integration Module
------------------------------------------
Wrapper that bridges the Crawler output and the XSSAttackBot.

Performance optimizations:
  • asyncio.to_thread for parallel endpoint chunk scanning  (Opt 1, 2)
  • Async latency measurement for adaptive timeout          (Opt 10)
  • Endpoint deduplication before scanning                   (Opt 6)
  • Higher concurrency (up to cpu*4, max 16)                (Opt 14)
  • DOM static scan performed once, not per chunk            (Opt 5)
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

from AttackBot.XSS_Attacks.xss_attack_bot import XSSAttackBot, XSSScanConfig, XSSFinding
from async_engine import measure_latency_async, run_sync

logger = logging.getLogger(__name__)


# ── Helper utilities ──────────────────────────────────────────────────────

def _split_list(items: list, n: int) -> List[list]:
    if n <= 1 or not items:
        return [items] if items else []
    k, m = divmod(len(items), n)
    chunks = [items[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]
    return [c for c in chunks if c]


def _crawled_to_xss_ep(crawled) -> Dict[str, Any]:
    if isinstance(crawled, dict):
        return {
            "path":       crawled.get("path", "/"),
            "method":     crawled.get("method", "GET"),
            "parameters": list(crawled.get("parameters", [])),
        }
    return {
        "path":       getattr(crawled, "path", "/"),
        "method":     getattr(crawled, "method", "GET"),
        "parameters": list(getattr(crawled, "parameters", [])),
    }


def _dedup_xss_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for ep in endpoints:
        key = (ep["path"], ep["method"], tuple(sorted(ep["parameters"])))
        if key not in seen:
            seen.add(key)
            out.append(ep)
    out.sort(key=lambda e: (e["path"], e["method"], tuple(sorted(e["parameters"]))))
    return out


# ── XSS Runner ────────────────────────────────────────────────────────────

class XSSRunner:
    """Integration layer around XSSAttackBot with async parallel scanning."""

    def __init__(
        self,
        target_url: str,
        project_dir: Optional[str] = None,
        config: Optional[XSSScanConfig] = None,
    ):
        self.target_url  = target_url.rstrip("/")
        self.project_dir = project_dir
        self.config = config or XSSScanConfig(
            verbose=False,
            timeout=8.0,
            delay_between_requests=0.05,
            skip_blind=True,
        )
        self._findings: List[XSSFinding] = []

    # ── Public API (sync) ─────────────────────────────────────────────

    def run(self, crawled_endpoints: Optional[List[Any]] = None) -> Dict[str, Any]:
        return run_sync(self.run_async(crawled_endpoints))

    # ── Async implementation ──────────────────────────────────────────

    async def run_async(
        self, crawled_endpoints: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        try:
            xss_endpoints: Optional[List[Dict[str, Any]]] = None
            if crawled_endpoints:
                xss_endpoints = [_crawled_to_xss_ep(ep) for ep in crawled_endpoints]
                for ep in xss_endpoints:
                    if not ep["parameters"]:
                        ep["parameters"] = ["q", "input", "search"]
                xss_endpoints = _dedup_xss_endpoints(xss_endpoints)

            endpoint_count = len(xss_endpoints) if xss_endpoints else 0
            logger.info("[XSSRunner] Starting XSS scan on %s — %d endpoints",
                        self.target_url, endpoint_count)

            if not xss_endpoints or endpoint_count == 0:
                bot = XSSAttackBot(
                    target_url=self.target_url,
                    project_dir=self.project_dir,
                    config=self.config,
                )
                self._findings = await asyncio.to_thread(bot.run_scan, None)
                return self._build_result(bot)

            # Adaptive timeout
            adapted_config = await self._adapt_timeout_async()

            # DOM static scan — once only (in a thread)
            dom_findings: List[XSSFinding] = []
            if self.project_dir:
                def _dom_scan():
                    dom_bot = XSSAttackBot(
                        target_url=self.target_url,
                        project_dir=self.project_dir,
                        config=adapted_config,
                    )
                    return dom_bot.run_scan(endpoints=[])
                dom_findings = await asyncio.to_thread(_dom_scan)

            # Parallel endpoint scanning
            n_workers = min(endpoint_count, max(2, (os.cpu_count() or 2) * 4), 16)
            if endpoint_count <= 2:
                n_workers = 1

            logger.info("[XSSRunner] Scanning %d endpoints with %d worker(s)",
                        endpoint_count, n_workers)

            all_findings: List[XSSFinding] = list(dom_findings)
            all_dicts: List[Dict[str, Any]] = []

            def _scan_chunk(chunk: List[Dict[str, Any]]):
                bot = XSSAttackBot(
                    target_url=self.target_url,
                    project_dir=None,
                    config=adapted_config,
                )
                findings = bot.run_scan(endpoints=chunk)
                return findings, bot.get_findings_as_dicts()

            if n_workers <= 1:
                findings, dicts = await asyncio.to_thread(_scan_chunk, xss_endpoints)
                all_findings.extend(findings)
                all_dicts.extend(dicts)
            else:
                chunks = _split_list(xss_endpoints, n_workers)
                tasks = [asyncio.to_thread(_scan_chunk, c) for c in chunks]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, res in enumerate(results):
                    if isinstance(res, Exception):
                        logger.warning("[XSSRunner] Chunk %d error: %s", i, res)
                    else:
                        all_findings.extend(res[0])
                        all_dicts.extend(res[1])

            self._findings = all_findings

            by_type: Dict[str, int] = Counter()
            for f in all_findings:
                by_type[f.xss_type] += 1
            summary = {"total_xss_findings": len(all_findings), "by_type": dict(by_type)}

            logger.info("[XSSRunner] XSS scan complete — %d finding(s)", len(all_findings))

            return {
                "success": True, "findings": all_findings,
                "findings_dicts": all_dicts, "summary": summary, "error": None,
            }

        except Exception as exc:
            logger.exception("[XSSRunner] XSS scan failed")
            return {
                "success": False, "findings": [], "findings_dicts": [],
                "summary": {"total_xss_findings": 0}, "error": str(exc),
            }

    # ── Accessors ─────────────────────────────────────────────────────

    @property
    def findings(self) -> List[XSSFinding]:
        return self._findings

    # ── Internal helpers ──────────────────────────────────────────────

    def _build_result(self, bot: XSSAttackBot) -> Dict[str, Any]:
        summary = bot.findings_summary()
        logger.info("[XSSRunner] XSS scan complete — %d finding(s)",
                    summary["total_xss_findings"])
        return {
            "success": True, "findings": self._findings,
            "findings_dicts": bot.get_findings_as_dicts(),
            "summary": summary, "error": None,
        }

    async def _adapt_timeout_async(self) -> XSSScanConfig:
        measured = await measure_latency_async(self.target_url)
        timeout = self.config.timeout
        if measured is not None:
            timeout = min(max(measured * 5, 3.0), 15.0)
            logger.info("[XSSRunner] Adaptive timeout: %.1fs (latency: %.3fs)",
                        timeout, measured)
        return XSSScanConfig(
            timeout=timeout,
            delay_between_requests=self.config.delay_between_requests,
            skip_blind=self.config.skip_blind,
            verbose=False,
        )
