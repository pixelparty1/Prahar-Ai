"""
attackbot_runner.py  –  Module 7
---------------------------------
Wrapper that bridges the Crawler output and the existing
SQLInjectionAttackBot without modifying any AttackBot code.

Responsibilities
~~~~~~~~~~~~~~~~
1. Accept ``target_url`` + a list of ``CrawledEndpoint`` from the crawler.
2. Convert them into ``DiscoveredEndpoint`` objects the bot understands.
3. Discover endpoints once, then scan chunks in parallel via asyncio+threads.
4. Merge results from parallel scans into a single ReportGenerator.
5. Return the merged ReportGenerator (and raw scan-log).

Performance optimizations:
  • asyncio.to_thread for parallel endpoint chunk scanning  (Opt 1, 2)
  • Adaptive timeout via async latency measurement          (Opt 10)
  • Endpoint deduplication before scanning                   (Opt 6)
  • Resource-aware concurrency (up to cpu*4, max 16)        (Opt 14)
  • Payloads loaded once per bot instance (smart cache)      (Opt 5, 13)
  • Each bot instance has its own requests.Session           (Opt 4)
  • Request dedup cache shared across chunks                 (Opt 6)

Does NOT modify any AttackBot detection logic.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from AttackBot.SQL_Injections.sql_injection_scanner import SQLInjectionAttackBot, ScanConfig, ScanLogEntry
from AttackBot.SQL_Injections.endpoint_finder import DiscoveredEndpoint
from AttackBot.SQL_Injections.report_generator import ReportGenerator
from crawler import CrawledEndpoint
from async_engine import measure_latency_async, run_sync

logger = logging.getLogger(__name__)


# ── Helper utilities ──────────────────────────────────────────────────────

def _split_list(items: list, n: int) -> List[list]:
    """Split *items* into *n* roughly equal chunks (no empty chunks)."""
    if n <= 1 or not items:
        return [items] if items else []
    k, m = divmod(len(items), n)
    chunks = [items[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]
    return [c for c in chunks if c]


def _to_discovered(crawled: CrawledEndpoint) -> DiscoveredEndpoint:
    """Convert a CrawledEndpoint → DiscoveredEndpoint."""
    return DiscoveredEndpoint(
        path=crawled.path,
        method=crawled.method,
        parameters=list(crawled.parameters),
        source_file=None,
        source_line=None,
        framework=None,
    )


def _dedup_endpoints(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
    """Remove duplicate endpoints by (path, method, params) key and sort deterministically."""
    seen: set = set()
    out: List[DiscoveredEndpoint] = []
    for ep in endpoints:
        key = (ep.path, ep.method, tuple(sorted(ep.parameters)))
        if key not in seen:
            seen.add(key)
            out.append(ep)
    out.sort(key=lambda e: (e.path, e.method, tuple(sorted(e.parameters))))
    return out


# ── Runner class ──────────────────────────────────────────────────────────

class AttackBotRunner:
    """
    Integration layer around SQLInjectionAttackBot with parallel
    endpoint scanning via asyncio + threads.

    Parameters
    ----------
    target_url : str
        The base URL of the live application (e.g. ``http://127.0.0.1:9000``).
    project_dir : str | None
        Path to the extracted project source tree.
    config : ScanConfig | None
        Custom scan configuration.
    """

    def __init__(
        self,
        target_url: str,
        project_dir: Optional[str] = None,
        config: Optional[ScanConfig] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.project_dir = project_dir
        self.config = config or ScanConfig(
            verbose=False,
            timeout=8.0,
            delay_between_requests=0.05,
        )
        self._bot: Optional[SQLInjectionAttackBot] = None
        self._report: Optional[ReportGenerator] = None
        self._scan_log: List[ScanLogEntry] = []

    # ── Public API (sync) ─────────────────────────────────────────────

    def run(
        self,
        crawled_endpoints: Optional[List[CrawledEndpoint]] = None,
        extra_discovered: Optional[List[DiscoveredEndpoint]] = None,
        probe_live: bool = True,
    ) -> Dict[str, Any]:
        """Execute the scan. Internally uses async for parallelism."""
        return run_sync(self.run_async(crawled_endpoints, extra_discovered, probe_live))

    # ── Async implementation ──────────────────────────────────────────

    async def run_async(
        self,
        crawled_endpoints: Optional[List[CrawledEndpoint]] = None,
        extra_discovered: Optional[List[DiscoveredEndpoint]] = None,
        probe_live: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a full AttackBot scan with parallel endpoint scanning.

        Returns
        -------
        dict  {success, report, scan_log, endpoints_scanned, error}
        """
        try:
            # ── Phase 1: Discover all endpoints (single pass) ─────────
            self._bot = SQLInjectionAttackBot(
                target_url=self.target_url,
                config=self.config,
            )

            extras: List[DiscoveredEndpoint] = []
            if crawled_endpoints:
                extras.extend(_to_discovered(c) for c in crawled_endpoints)
            if extra_discovered:
                extras.extend(extra_discovered)

            self._bot.discover_endpoints(
                project_dir=self.project_dir,
                extra_endpoints=extras if extras else None,
                probe_live=probe_live,
            )

            all_endpoints = _dedup_endpoints(list(self._bot.endpoints))
            static_findings = list(self._bot.get_report().static_findings)
            endpoint_count = len(all_endpoints)

            logger.info(
                "[AttackBotRunner] %d endpoints discovered — scanning %s",
                endpoint_count, self.target_url,
            )

            if endpoint_count == 0:
                return {
                    "success": True,
                    "report": self._bot.get_report(),
                    "scan_log": [],
                    "endpoints_scanned": 0,
                    "error": "No endpoints discovered — nothing to scan.",
                }

            # ── Phase 2: Adaptive timeout (async latency probe) ───────
            adapted_config = await self._adapt_timeout_async()

            # ── Phase 3: Parallel endpoint scanning ───────────────────
            n_workers = min(
                endpoint_count,
                max(2, (os.cpu_count() or 2) * 4),
                16,
            )
            if endpoint_count <= 2:
                n_workers = 1

            logger.info(
                "[AttackBotRunner] Scanning %d endpoints with %d parallel worker(s)",
                endpoint_count, n_workers,
            )

            merged_report = ReportGenerator()
            merged_report.set_target(self.target_url)
            merged_report.mark_start()
            merged_report.add_static_findings(static_findings)
            all_scan_logs: List[ScanLogEntry] = []

            def _scan_chunk(chunk: List[DiscoveredEndpoint]):
                """Each thread gets its own bot instance (own Session)."""
                bot = SQLInjectionAttackBot(
                    target_url=self.target_url,
                    config=adapted_config,
                )
                bot.endpoints = list(chunk)
                report = bot.run_scan()
                return report.results, list(bot.scan_log)

            if n_workers <= 1:
                results, logs = await asyncio.to_thread(_scan_chunk, all_endpoints)
                merged_report.add_results(results)
                all_scan_logs.extend(logs)
            else:
                chunks = _split_list(all_endpoints, n_workers)
                tasks = [
                    asyncio.to_thread(_scan_chunk, chunk)
                    for chunk in chunks
                ]
                results_list = await asyncio.gather(*tasks, return_exceptions=True)
                for i, res in enumerate(results_list):
                    if isinstance(res, Exception):
                        logger.warning("[AttackBotRunner] Chunk %d error: %s", i, res)
                    else:
                        results, logs = res
                        merged_report.add_results(results)
                        all_scan_logs.extend(logs)

            merged_report.mark_end()
            self._report = merged_report
            self._scan_log = all_scan_logs

            return {
                "success": True,
                "report": merged_report,
                "scan_log": all_scan_logs,
                "endpoints_scanned": endpoint_count,
                "error": None,
            }

        except Exception as exc:
            logger.exception("[AttackBotRunner] Scan failed")
            return {
                "success": False,
                "report": None,
                "scan_log": [],
                "endpoints_scanned": 0,
                "error": str(exc),
            }

    # ── Accessors ─────────────────────────────────────────────────────

    @property
    def report(self) -> Optional[ReportGenerator]:
        return self._report

    @property
    def scan_log(self) -> List[ScanLogEntry]:
        return self._scan_log

    @property
    def bot(self) -> Optional[SQLInjectionAttackBot]:
        return self._bot

    # ── Adaptive timeout (async) ──────────────────────────────────────

    async def _adapt_timeout_async(self) -> ScanConfig:
        """Measure server latency asynchronously and adapt timeout."""
        measured = await measure_latency_async(self.target_url)
        timeout = self.config.timeout
        if measured is not None:
            timeout = min(max(measured * 5, 3.0), 15.0)
            logger.info(
                "[AttackBotRunner] Adaptive timeout: %.1fs (avg latency: %.3fs)",
                timeout, measured,
            )
        return ScanConfig(
            timeout=timeout,
            delay_between_requests=self.config.delay_between_requests,
            max_payloads_per_category=self.config.max_payloads_per_category,
            skip_time_based=self.config.skip_time_based,
            skip_destructive_sim=self.config.skip_destructive_sim,
            user_agent=self.config.user_agent,
            verify_ssl=self.config.verify_ssl,
            follow_redirects=self.config.follow_redirects,
            verbose=False,
        )
