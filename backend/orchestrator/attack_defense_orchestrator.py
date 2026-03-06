"""
attack_defense_orchestrator.py — Unified Attack + Defense runner
----------------------------------------------------------------
Launches AttackBot modules and DefendBot listeners simultaneously.
Each attack result triggers the corresponding defense bot via the
EventBus so that the defense simulation happens *immediately* after
each attack completes.

Does NOT modify any existing attack or defense logic — it only
consumes their public APIs.

Usage::

    orch = AttackDefenseOrchestrator(target_url="http://example.com")
    result = orch.run(crawled_endpoints=endpoints)
    # result contains both attack findings and defense verdicts
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from .event_bus import AttackEvent, EventBus

logger = logging.getLogger(__name__)


# ── Pretty battle-log printer ────────────────────────────────────────────

_ATTACK_LABELS = {
    "SQL_INJECTION": "SQL Injection",
    "XSS": "XSS",
    "CORS": "CORS Misconfiguration",
    "DDOS": "DDoS",
}


def _print_battle_header(attack_type: str) -> None:
    label = _ATTACK_LABELS.get(attack_type, attack_type)
    print(f"\n{'─' * 60}")
    print(f"  ⚔  AttackBot: {label} scan complete")
    print(f"{'─' * 60}")


def _print_defense_result(attack_type: str, summary: Dict[str, Any]) -> None:
    label = _ATTACK_LABELS.get(attack_type, attack_type)
    mitigated = summary.get("total_mitigated",
                 summary.get("attacks_blocked",
                 summary.get("attacks_mitigated", 0)))
    total = summary.get("total_evaluated",
             summary.get("total_attacks_analyzed", 0))
    rate = summary.get("defense_rate", "N/A")

    print(f"  🛡  DefendBot: {label} defense activated")
    print(f"      Mitigated {mitigated}/{total} attacks ({rate}% defense rate)")


def _print_battle_entries(entries: list) -> None:
    """Print individual attack/defense battle log entries."""
    for entry in entries[:10]:  # cap to avoid flooding
        if isinstance(entry, dict):
            # SQL / CORS structured battle log
            attack_info = entry.get("attack", {})
            defense_info = entry.get("defense", {})
            result = entry.get("result", "")
            a_type = attack_info.get("type", attack_info.get("issue_type", "Unknown"))
            endpoint = attack_info.get("endpoint", "?")
            technique = defense_info.get("technique", "?")
            action = defense_info.get("action", "?")
            print(f"      [{action}] {a_type} @ {endpoint} → {technique}")
        elif isinstance(entry, str):
            # XSS / DDoS string battle log
            print(f"      {entry}")
    if len(entries) > 10:
        print(f"      ... and {len(entries) - 10} more")


# ── Orchestrator ──────────────────────────────────────────────────────────

class AttackDefenseOrchestrator:
    """
    Orchestrates parallel AttackBot execution with real-time DefendBot
    response via an event bus.

    Parameters
    ----------
    target_url : str
        The target URL to scan.
    project_dir : str | None
        Optional project directory for static analysis.
    verbose : bool
        If True, print detailed battle log entries.
    """

    def __init__(
        self,
        target_url: str,
        project_dir: Optional[str] = None,
        verbose: bool = True,
    ) -> None:
        self.target_url = target_url.strip().rstrip("/")
        self.project_dir = project_dir
        self.verbose = verbose

        self._bus = EventBus()
        self._defense_results: Dict[str, Dict[str, Any]] = {}
        self._battle_logs: Dict[str, list] = {}
        self._attack_results: Dict[str, Dict[str, Any]] = {}

        # Register defense listeners
        self._bus.subscribe("SQL_INJECTION", self._handle_sql_defense)
        self._bus.subscribe("XSS", self._handle_xss_defense)
        self._bus.subscribe("CORS", self._handle_cors_defense)
        self._bus.subscribe("DDOS", self._handle_ddos_defense)

    @property
    def event_bus(self) -> EventBus:
        """Read-only access to the event bus (used by NarratorBot)."""
        return self._bus

    # ── Defense event handlers ────────────────────────────────────────

    def _handle_sql_defense(self, event: AttackEvent) -> None:
        from DefendBot.sql_defense_bot import SQLDefenseBot

        _print_battle_header("SQL_INJECTION")
        n_findings = len(event.raw_result.get("report", {}).get("vulnerabilities", []) if isinstance(event.raw_result.get("report"), dict) else [])
        print(f"      Findings: {n_findings} SQL injection vulnerabilities")

        scan_log = event.scan_log
        if not scan_log:
            print("      DefendBot: No scan log available — skipping defense")
            return

        bot = SQLDefenseBot(target_url=event.target_url)
        bot.analyze_scan_log(scan_log)
        results = bot.get_results()
        summary = bot.get_summary()
        battle_log = bot.get_battle_log()

        self._defense_results["sql"] = results
        self._battle_logs["sql"] = battle_log

        _print_defense_result("SQL_INJECTION", summary)
        if self.verbose and battle_log:
            _print_battle_entries(battle_log)

    def _handle_xss_defense(self, event: AttackEvent) -> None:
        from DefendBot.xss_defense_bot import XSSDefenseBot

        _print_battle_header("XSS")
        print(f"      Findings: {len(event.findings_dicts)} XSS vulnerabilities")

        if not event.findings_dicts:
            print("      DefendBot: No findings — skipping defense")
            return

        bot = XSSDefenseBot(target_url=event.target_url)
        bot.analyze_findings(event.findings_dicts)
        results = bot.get_results()
        summary = bot.get_summary()
        battle_log = bot.get_battle_log()

        self._defense_results["xss"] = results
        self._battle_logs["xss"] = battle_log

        _print_defense_result("XSS", summary)
        if self.verbose and battle_log:
            _print_battle_entries(battle_log)

    def _handle_cors_defense(self, event: AttackEvent) -> None:
        from DefendBot.cors_defense_bot import CORSDefenseBot

        _print_battle_header("CORS")
        print(f"      Findings: {len(event.findings_dicts)} CORS misconfigurations")

        if not event.findings_dicts:
            print("      DefendBot: No findings — skipping defense")
            return

        bot = CORSDefenseBot(target_url=event.target_url)
        bot.analyze_findings(event.findings_dicts)
        results = bot.get_results()
        summary = bot.get_summary()
        battle_log = bot.get_battle_log()

        self._defense_results["cors"] = results
        self._battle_logs["cors"] = battle_log

        _print_defense_result("CORS", summary)
        if self.verbose and battle_log:
            _print_battle_entries(battle_log)

    def _handle_ddos_defense(self, event: AttackEvent) -> None:
        from DefendBot.ddos_defense_bot import DDoSDefenseBot

        _print_battle_header("DDOS")
        print(f"      Findings: {len(event.findings_dicts)} DDoS vulnerabilities")

        if not event.findings_dicts:
            print("      DefendBot: No findings — skipping defense")
            return

        bot = DDoSDefenseBot(target_url=event.target_url)
        bot.analyze_findings(event.findings_dicts)
        results = bot.get_results()
        summary = bot.get_summary()
        battle_log = bot.get_battle_log()

        self._defense_results["ddos"] = results
        self._battle_logs["ddos"] = battle_log

        _print_defense_result("DDOS", summary)
        if self.verbose and battle_log:
            _print_battle_entries(battle_log)

    # ── Attack tasks (each emits events upon completion) ──────────────

    def _sqli_attack_task(self, endpoints: Optional[list]) -> Dict[str, Any]:
        from attackbot_runner import AttackBotRunner

        runner = AttackBotRunner(
            target_url=self.target_url,
            project_dir=self.project_dir,
        )
        result = runner.run(
            crawled_endpoints=list(endpoints) if endpoints else None,
            probe_live=True,
        )
        self._attack_results["sql"] = result

        # Emit event so defense listener fires immediately in this thread
        if result.get("success"):
            self._bus.publish(AttackEvent(
                attack_type="SQL_INJECTION",
                target_url=self.target_url,
                scan_log=result.get("scan_log"),
                summary=result.get("report", {}).get("scan_summary", {}) if isinstance(result.get("report"), dict) else {},
                raw_result=result,
            ))

        return result

    def _xss_attack_task(self, endpoints: Optional[list]) -> Dict[str, Any]:
        from xss_runner import XSSRunner

        xr = XSSRunner(target_url=self.target_url, project_dir=self.project_dir)
        result = xr.run(
            crawled_endpoints=list(endpoints) if endpoints else None,
        )
        self._attack_results["xss"] = result

        if result.get("success"):
            self._bus.publish(AttackEvent(
                attack_type="XSS",
                target_url=self.target_url,
                findings_dicts=result.get("findings_dicts", []),
                summary=result.get("summary", {}),
                raw_result=result,
            ))

        return result

    def _cors_attack_task(self, endpoints: Optional[list]) -> Dict[str, Any]:
        from cors_runner import CORSRunner

        cr = CORSRunner(target_url=self.target_url)
        result = cr.run(
            crawled_endpoints=list(endpoints) if endpoints else None,
        )
        self._attack_results["cors"] = result

        if result.get("success"):
            self._bus.publish(AttackEvent(
                attack_type="CORS",
                target_url=self.target_url,
                findings_dicts=result.get("findings_dicts", []),
                summary=result.get("summary", {}),
                raw_result=result,
            ))

        return result

    def _ddos_attack_task(self, endpoints: Optional[list]) -> Dict[str, Any]:
        from ddos_runner import DDoSRunner

        dr = DDoSRunner(target_url=self.target_url)
        result = dr.run(
            crawled_endpoints=list(endpoints) if endpoints else None,
        )
        self._attack_results["ddos"] = result

        if result.get("success"):
            self._bus.publish(AttackEvent(
                attack_type="DDOS",
                target_url=self.target_url,
                findings_dicts=result.get("findings_dicts", []),
                summary=result.get("summary", {}),
                raw_result=result,
            ))

        return result

    # ── Main execution ────────────────────────────────────────────────

    def run(
        self,
        crawled_endpoints: Optional[list] = None,
        report_svc: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Run all attacks concurrently; defense listeners fire automatically
        as each attack thread completes.

        Parameters
        ----------
        crawled_endpoints : list | None
            Pre-crawled endpoint list. If None, each runner discovers its own.
        report_svc : ReportService | None
            If provided, attack and defense results are set on it directly.

        Returns
        -------
        dict
            Combined result with attack and defense data.
        """
        from async_engine import run_sync

        frozen = tuple(crawled_endpoints) if crawled_endpoints else None
        t0 = time.time()

        print("\n" + "═" * 60)
        print("  PRAHAAR AI — ATTACK vs DEFENSE BATTLE SIMULATION")
        print("═" * 60)
        print(f"  Target: {self.target_url}")
        print(f"  Mode  : Simultaneous Attack + Defense")
        print("═" * 60)
        print("\nLaunching all attack modules in parallel...")
        print("Defense bots are listening and will react in real time.\n")

        # Each attack task runs in its own thread via asyncio.to_thread.
        # When a task finishes, it calls bus.publish() synchronously
        # *in that same thread*, which invokes the defense handler
        # immediately — so defense is triggered right after attack.

        async def _run_parallel():
            return await asyncio.gather(
                asyncio.to_thread(self._sqli_attack_task, frozen),
                asyncio.to_thread(self._xss_attack_task, frozen),
                asyncio.to_thread(self._cors_attack_task, frozen),
                asyncio.to_thread(self._ddos_attack_task, frozen),
                return_exceptions=True,
            )

        results = run_sync(_run_parallel())
        sqli_res, xss_res, cors_res, ddos_res = results

        elapsed = time.time() - t0

        # ── Feed results into ReportService if provided ───────────
        if report_svc is not None:
            self._populate_report_service(
                report_svc, sqli_res, xss_res, cors_res, ddos_res,
            )

        # ── Print final battle summary ────────────────────────────
        self._print_final_summary(elapsed)

        return {
            "success": True,
            "elapsed_seconds": round(elapsed, 1),
            "attack_results": self._attack_results,
            "defense_results": self._defense_results,
            "battle_logs": self._battle_logs,
            "event_log": self._bus.event_log,
        }

    # ── Report service population ─────────────────────────────────────

    def _populate_report_service(
        self, svc: Any,
        sqli_res: Any, xss_res: Any, cors_res: Any, ddos_res: Any,
    ) -> None:
        """Push attack + defense results into a ReportService instance."""

        # SQLi attack results
        if not isinstance(sqli_res, Exception) and sqli_res.get("success"):
            if sqli_res.get("report") is not None:
                svc.set_live_scan_report(sqli_res["report"])
                svc.add_event("live_scan",
                    f"SQL scan complete — {sqli_res.get('endpoints_scanned', 0)} endpoints scanned")
        elif isinstance(sqli_res, Exception):
            svc.add_event("live_scan", f"SQL scan failed: {sqli_res}", success=False)

        # XSS attack results
        if not isinstance(xss_res, Exception) and xss_res.get("success"):
            svc.set_xss_findings(xss_res.get("findings_dicts") or [])
            total_xss = (xss_res.get("summary") or {}).get("total_xss_findings", 0)
            svc.add_event("xss_scan", f"XSS scan complete — {total_xss} finding(s)")
        elif isinstance(xss_res, Exception):
            svc.add_event("xss_scan", f"XSS scan failed: {xss_res}", success=False)

        # CORS attack results
        if not isinstance(cors_res, Exception) and cors_res.get("success"):
            svc.set_cors_findings(cors_res.get("findings_dicts") or [])
            total_cors = (cors_res.get("summary") or {}).get("total_cors_findings", 0)
            svc.add_event("cors_scan", f"CORS scan complete — {total_cors} finding(s)")
        elif isinstance(cors_res, Exception):
            svc.add_event("cors_scan", f"CORS scan failed: {cors_res}", success=False)

        # DDoS attack results
        if not isinstance(ddos_res, Exception) and ddos_res.get("success"):
            svc.set_ddos_findings(ddos_res.get("findings_dicts") or [])
            total_ddos = (ddos_res.get("summary") or {}).get("total_ddos_findings", 0)
            svc.add_event("ddos_scan", f"DDoS scan complete — {total_ddos} finding(s)")
        elif isinstance(ddos_res, Exception):
            svc.add_event("ddos_scan", f"DDoS scan failed: {ddos_res}", success=False)

        # Defense results
        if "sql" in self._defense_results:
            svc.set_defense_results(self._defense_results["sql"])
            ds = (self._defense_results["sql"].get("summary") or {})
            svc.add_event("defense_sim",
                f"SQL defense complete — {ds.get('attacks_blocked', 0)} blocked, "
                f"{ds.get('defense_rate', 0)}% defense rate")

        if "xss" in self._defense_results:
            svc.set_xss_defense_results(self._defense_results["xss"])
            ds = (self._defense_results["xss"].get("summary") or {})
            svc.add_event("xss_defense_sim",
                f"XSS defense complete — {ds.get('total_mitigated', 0)} mitigated, "
                f"{ds.get('defense_rate', 0)}% defense rate")

        if "cors" in self._defense_results:
            svc.set_cors_defense_results(self._defense_results["cors"])
            ds = (self._defense_results["cors"].get("summary") or {})
            svc.add_event("cors_defense_sim",
                f"CORS defense complete — {ds.get('attacks_mitigated', 0)} mitigated, "
                f"{ds.get('defense_rate', 0)}% defense rate")

        if "ddos" in self._defense_results:
            svc.set_ddos_defense_results(self._defense_results["ddos"])
            ds = (self._defense_results["ddos"].get("summary") or {})
            svc.add_event("ddos_defense_sim",
                f"DDoS defense complete — {ds.get('total_mitigated', 0)} mitigated, "
                f"{ds.get('defense_rate', 0)}% defense rate")

    # ── Summary printer ───────────────────────────────────────────────

    def _print_final_summary(self, elapsed: float) -> None:
        print(f"\n{'═' * 60}")
        print("  BATTLE SIMULATION RESULTS")
        print(f"{'═' * 60}")
        print(f"  Duration: {elapsed:.1f}s")

        for label, key, mitigated_key, total_key in [
            ("SQL Injection", "sql", "attacks_blocked", "total_attacks_analyzed"),
            ("XSS", "xss", "total_mitigated", "total_evaluated"),
            ("CORS", "cors", "attacks_mitigated", "total_attacks_analyzed"),
            ("DDoS", "ddos", "total_mitigated", "total_evaluated"),
        ]:
            dr = self._defense_results.get(key)
            if dr:
                s = dr.get("summary", {})
                m = s.get(mitigated_key, 0)
                t = s.get(total_key, 0)
                r = s.get("defense_rate", "N/A")
                print(f"  {label:20s}: {m}/{t} mitigated ({r}% defense rate)")
            else:
                ar = self._attack_results.get(key)
                if ar and not isinstance(ar, Exception):
                    if ar.get("success"):
                        print(f"  {label:20s}: Attack ran — no findings to defend")
                    else:
                        print(f"  {label:20s}: Attack error — {ar.get('error', 'unknown')}")
                elif isinstance(ar, Exception):
                    print(f"  {label:20s}: Attack failed — {ar}")
                else:
                    print(f"  {label:20s}: Not executed")

        print(f"{'═' * 60}\n")
