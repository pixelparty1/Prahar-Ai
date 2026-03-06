"""
attackbot_runner.py  –  Module 7
---------------------------------
Wrapper that bridges the Crawler output and the existing
SQLInjectionAttackBot without modifying any AttackBot code.

Responsibilities
~~~~~~~~~~~~~~~~
1. Accept ``target_url`` + a list of ``CrawledEndpoint`` from the crawler.
2. Convert them into ``DiscoveredEndpoint`` objects the bot understands.
3. Call ``bot.discover_endpoints(extra_endpoints=...)`` + ``bot.run_scan()``.
4. Return the ReportGenerator (and raw scan-log).
"""

from __future__ import annotations

import logging
import sys
import os
from typing import Any, Dict, List, Optional

# Ensure the AttackBot package is importable
_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from AttackBot.SQL_Injections.sql_injection_scanner import SQLInjectionAttackBot, ScanConfig, ScanLogEntry
from AttackBot.SQL_Injections.endpoint_finder import DiscoveredEndpoint
from AttackBot.SQL_Injections.report_generator import ReportGenerator
from crawler import CrawledEndpoint

logger = logging.getLogger(__name__)


# ── Conversion helper ─────────────────────────────────────────────────────

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


# ── Runner class ──────────────────────────────────────────────────────────

class AttackBotRunner:
    """
    Thin integration layer around SQLInjectionAttackBot.

    Parameters
    ----------
    target_url : str
        The base URL of the live application (e.g. ``http://127.0.0.1:9000``).
    project_dir : str | None
        Path to the extracted project source tree (for static endpoint
        discovery and static code analysis).  Optional.
    config : ScanConfig | None
        Custom scan configuration.  Falls back to quiet defaults if omitted.
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

    # ── Public API ────────────────────────────────────────────────────

    def run(
        self,
        crawled_endpoints: Optional[List[CrawledEndpoint]] = None,
        extra_discovered: Optional[List[DiscoveredEndpoint]] = None,
        probe_live: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a full AttackBot scan.

        Parameters
        ----------
        crawled_endpoints : list[CrawledEndpoint] | None
            Endpoints produced by ``crawler.crawl()``.
        extra_discovered : list[DiscoveredEndpoint] | None
            Any additional manually-supplied endpoints.
        probe_live : bool
            Whether to let the bot's built-in live prober run.

        Returns
        -------
        dict
            ``{success, report, scan_log, error}``
            ``report`` is a ReportGenerator instance if success.
        """
        try:
            self._bot = SQLInjectionAttackBot(
                target_url=self.target_url,
                config=self.config,
            )

            # Build the extra_endpoints list
            extras: List[DiscoveredEndpoint] = []
            if crawled_endpoints:
                extras.extend(_to_discovered(c) for c in crawled_endpoints)
            if extra_discovered:
                extras.extend(extra_discovered)

            # Discover endpoints (static + live + extras)
            self._bot.discover_endpoints(
                project_dir=self.project_dir,
                extra_endpoints=extras if extras else None,
                probe_live=probe_live,
            )

            endpoint_count = len(self._bot.endpoints)
            logger.info(
                "[AttackBotRunner] %d endpoints discovered — starting scan on %s",
                endpoint_count,
                self.target_url,
            )

            if endpoint_count == 0:
                return {
                    "success": True,
                    "report": self._bot.get_report(),
                    "scan_log": [],
                    "endpoints_scanned": 0,
                    "error": "No endpoints discovered — nothing to scan.",
                }

            # Run the scan
            self._report = self._bot.run_scan()
            self._scan_log = list(self._bot.scan_log)

            return {
                "success": True,
                "report": self._report,
                "scan_log": self._scan_log,
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
