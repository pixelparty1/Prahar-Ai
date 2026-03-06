"""
bot_orchestrator.py  –  Module 11
-----------------------------------
Architecture-preparation layer that manages multiple bot types
(AttackBot, and in future DefendBot + LogBot).

Currently only integrates **AttackBot**.  The design is extensible:
register new bot types via ``register_bot()`` and the orchestrator
will invoke them in sequence during ``run_all()``.

Does NOT modify any existing AttackBot code.
"""

from __future__ import annotations

import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

logger = logging.getLogger(__name__)


# ── Bot interface (abstract) ──────────────────────────────────────────────

class BotPlugin(ABC):
    """
    Every bot that the orchestrator manages must implement this interface.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name, e.g. 'AttackBot'."""
        ...

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the bot's logic.

        Parameters
        ----------
        context : dict
            Shared pipeline context containing at least:
              • ``target_url``   — live server URL (may be None)
              • ``project_dir``  — extracted source directory
              • ``upload_id``    — unique upload identifier

        Returns
        -------
        dict
            ``{success: bool, data: Any, error: str|None}``
        """
        ...


# ── AttackBot plugin ──────────────────────────────────────────────────────

class AttackBotPlugin(BotPlugin):
    """
    Wraps AttackBotRunner + StaticScanRunner behind the BotPlugin API.
    """

    @property
    def name(self) -> str:
        return "AttackBot"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        from attackbot_runner import AttackBotRunner
        from static_scan_runner import StaticScanRunner
        from crawler import Crawler

        target_url: Optional[str] = context.get("target_url")
        project_dir: Optional[str] = context.get("project_dir")
        results: Dict[str, Any] = {
            "live_scan": None,
            "static_scan": None,
            "crawled_endpoints": [],
        }

        # ── Live scan ────────────────────────────────────────────────
        if target_url:
            try:
                cr = Crawler(target_url)
                crawled = cr.crawl()
                results["crawled_endpoints"] = cr.get_endpoints_as_dicts()

                runner = AttackBotRunner(
                    target_url=target_url,
                    project_dir=project_dir,
                )
                live = runner.run(crawled_endpoints=crawled, probe_live=True)
                results["live_scan"] = live
            except Exception as exc:
                logger.warning("[AttackBotPlugin] Live scan error: %s", exc)
                results["live_scan"] = {"success": False, "error": str(exc)}

        # ── Static scan ──────────────────────────────────────────────
        if project_dir:
            try:
                static = StaticScanRunner(project_dir).run()
                results["static_scan"] = static
            except Exception as exc:
                logger.warning("[AttackBotPlugin] Static scan error: %s", exc)
                results["static_scan"] = {"success": False, "error": str(exc)}

        success = bool(
            (results["live_scan"] and results["live_scan"].get("success"))
            or (results["static_scan"] and results["static_scan"].get("success"))
        )

        return {
            "success": success,
            "data": results,
            "error": None if success else "Both live and static scans failed.",
        }


# ── Future stubs ──────────────────────────────────────────────────────────

class DefendBotPlugin(BotPlugin):
    """Placeholder for future DefendBot integration."""

    @property
    def name(self) -> str:
        return "DefendBot"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("[DefendBotPlugin] Not yet implemented — skipping.")
        return {"success": True, "data": None, "error": None}


class LogBotPlugin(BotPlugin):
    """Placeholder for future LogBot integration."""

    @property
    def name(self) -> str:
        return "LogBot"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("[LogBotPlugin] Not yet implemented — skipping.")
        return {"success": True, "data": None, "error": None}


# ── Orchestrator ──────────────────────────────────────────────────────────

class BotOrchestrator:
    """
    Registry + runner for multiple bot plugins.

    Usage
    -----
    >>> orch = BotOrchestrator()
    >>> orch.register_bot(AttackBotPlugin())
    >>> results = orch.run_all(context={...})
    """

    def __init__(self):
        self._bots: List[BotPlugin] = []

    # ── Registration ──────────────────────────────────────────────────

    def register_bot(self, bot: BotPlugin) -> None:
        """Add a bot plugin to the execution list."""
        self._bots.append(bot)
        logger.info("[BotOrchestrator] Registered bot: %s", bot.name)

    def register_defaults(self) -> None:
        """Register all currently-available bot plugins."""
        self.register_bot(AttackBotPlugin())
        # Future:
        # self.register_bot(DefendBotPlugin())
        # self.register_bot(LogBotPlugin())

    # ── Execution ─────────────────────────────────────────────────────

    def run_all(self, context: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Execute every registered bot in sequence.

        Parameters
        ----------
        context : dict
            Shared pipeline state (target_url, project_dir, upload_id, …).

        Returns
        -------
        dict[str, dict]
            Mapping of bot name → result dict.
        """
        results: Dict[str, Dict[str, Any]] = {}

        for bot in self._bots:
            logger.info("[BotOrchestrator] Running %s …", bot.name)
            try:
                result = bot.execute(context)
                results[bot.name] = result
                status = "OK" if result.get("success") else "FAIL"
                logger.info("[BotOrchestrator] %s → %s", bot.name, status)
            except Exception as exc:
                logger.exception("[BotOrchestrator] %s raised an exception", bot.name)
                results[bot.name] = {
                    "success": False,
                    "data": None,
                    "error": str(exc),
                }

        return results

    # ── Introspection ─────────────────────────────────────────────────

    @property
    def registered_bots(self) -> List[str]:
        return [b.name for b in self._bots]
