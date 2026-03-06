"""
scan_controller.py  –  Module 10
----------------------------------
Main pipeline orchestrator that wires together every module from
Prompt 1 (infrastructure) and Prompt 2 (scanning layer).

Full workflow
~~~~~~~~~~~~~
1.  Upload     → ``upload_handler.UploadHandler``
2.  Detect     → ``framework_detector.FrameworkDetector``
3.  Sandbox    → ``sandbox_manager.SandboxManager``
4.  Crawl      → ``crawler.Crawler``
5.  Live scan  → ``attackbot_runner.AttackBotRunner``
6.  Static     → ``static_scan_runner.StaticScanRunner``
7.  Report     → ``report_service.ReportService``
8.  Cleanup    → ``cleanup_manager.CleanupManager``

Does NOT modify any existing AttackBot code.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from typing import Any, Dict, Optional

_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from upload_handler import UploadHandler
from framework_detector import FrameworkDetector
from sandbox_manager import SandboxManager
from crawler import Crawler
from attackbot_runner import AttackBotRunner
from xss_runner import XSSRunner
from cors_runner import CORSRunner
from ddos_runner import DDoSRunner
from static_scan_runner import StaticScanRunner
from report_service import ReportService
from cleanup_manager import CleanupManager
from AttackBot.SQL_Injections.sql_injection_scanner import ScanConfig
from async_engine import run_sync
from DefendBot.sql_defense_bot import SQLDefenseBot
from DefendBot.cors_defense_bot import CORSDefenseBot
from DefendBot.xss_defense_bot import XSSDefenseBot
from DefendBot.ddos_defense_bot import DDoSDefenseBot

logger = logging.getLogger(__name__)

# Reduce noise from HTTP libraries during parallel scanning
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)


class ScanController:
    """
    Drives the complete scan pipeline from ZIP upload to final JSON report.

    Parameters
    ----------
    report_dir : str
        Directory where final reports are saved.  Created if missing.
    scan_config : ScanConfig | None
        Optional custom scan configuration passed to AttackBotRunner.
    """

    def __init__(self, report_dir: str = "reports", scan_config: Optional[ScanConfig] = None):
        self.report_dir = os.path.abspath(report_dir)
        os.makedirs(self.report_dir, exist_ok=True)
        self._scan_config = scan_config

        # Sub-modules (stateless singletons for the infra layer)
        self._uploader = UploadHandler()
        self._detector = FrameworkDetector()
        self._sandbox = SandboxManager()

    # ── Public: full pipeline ─────────────────────────────────────────

    def run(self, zip_path: str) -> Dict[str, Any]:
        """
        Execute the full pipeline for a single ZIP upload.

        Parameters
        ----------
        zip_path : str
            Path to the ZIP file to scan.

        Returns
        -------
        dict
            ``{success, report_path, report, summary, error}``
        """
        t0 = time.time()
        ctx = _PipelineContext()

        report_svc = ReportService()

        try:
            # ── Step 1: Upload / Extract ──────────────────────────────
            report_svc.add_event("upload", f"Extracting {os.path.basename(zip_path)}")
            up = self._uploader.handle_zip(zip_path)
            if not up["success"]:
                return self._fail(f"Upload failed: {up['error']}", report_svc)
            ctx.upload_dir = up["project_dir"]
            ctx.upload_id = up["upload_id"]
            report_svc._upload_id = ctx.upload_id
            report_svc.add_event("upload", f"Extracted to {ctx.upload_dir}")
            logger.info("[ScanController] Step 1 OK — extracted to %s", ctx.upload_dir)

            # ── Step 2: Detect framework ──────────────────────────────
            report_svc.add_event("detect", "Detecting framework")
            fw = self._detector.detect(ctx.upload_dir)
            ctx.framework_info = fw
            report_svc.add_event("detect", f"Detected: {fw['framework']}")
            logger.info("[ScanController] Step 2 OK — framework=%s", fw["framework"])

            # ── Step 3: Launch sandbox ────────────────────────────────
            report_svc.add_event("sandbox", "Launching sandbox server")
            sb = self._sandbox.launch(ctx.upload_dir, fw)
            if sb["success"]:
                ctx.sandbox_id = sb["sandbox_id"]
                ctx.target_url = sb["target_url"]
                ctx.sandbox_pid = sb["process_id"]
                ctx.sandbox_dir = self._sandbox.get_instance(ctx.sandbox_id).sandbox_dir if ctx.sandbox_id else None
                report_svc._target_url = ctx.target_url
                report_svc.add_event("sandbox", f"Server running at {ctx.target_url}")
                report_svc.set_sandbox_status(
                    success=True,
                    target_url=ctx.target_url,
                    logs=sb.get("logs", []),
                )
                logger.info("[ScanController] Step 3 OK \u2014 %s (PID %s)", ctx.target_url, ctx.sandbox_pid)
            else:
                sandbox_err = sb.get("error", "Unknown sandbox error")
                sandbox_logs = sb.get("logs", [])
                report_svc.add_event("sandbox", f"Sandbox failed: {sandbox_err}", success=False)
                report_svc.set_sandbox_status(
                    success=False,
                    error=sandbox_err,
                    logs=sandbox_logs,
                    fallback="Static code analysis performed instead.",
                )
                logger.warning("[ScanController] Step 3 WARN \u2014 sandbox failed: %s (will do static-only scan)", sandbox_err)
                for ln in sandbox_logs[-5:]:
                    logger.warning("  [sandbox log] %s", ln)

            # ── Steps 4/5/5b/5c/6: Crawl + all scans ─────────────────────
            # Static scan does NOT need crawl results, so it starts immediately
            # while crawl is still running.  Live scans start once crawl finishes.
            # Everything wrapped in one async block to maximise concurrency.
            async def _crawl_and_scan():
                # Launch static scan immediately (doesn't need endpoints)
                report_svc.add_event("static_scan", "Running static code analysis")
                static_task = asyncio.to_thread(self._run_static, ctx.upload_dir)

                # Crawl in parallel with static scan
                crawled = []
                if ctx.target_url:
                    report_svc.add_event("crawl", f"Crawling {ctx.target_url}")
                    try:
                        cr = Crawler(ctx.target_url, max_pages=50, timeout=5.0)
                        crawled = await asyncio.to_thread(cr.crawl)
                        report_svc.set_crawled_endpoints(cr.get_endpoints_as_dicts())
                        report_svc.add_event("crawl", f"Found {len(crawled)} endpoints")
                        logger.info("[ScanController] Step 4 OK — %d endpoints crawled", len(crawled))
                    except Exception as exc:
                        report_svc.add_event("crawl", f"Crawl error: {exc}", success=False)
                        logger.warning("[ScanController] Step 4 WARN — crawl error: %s", exc)
                else:
                    report_svc.add_event("crawl", "Skipped (no live server)", success=False)

                frozen = tuple(crawled)
                tasks = {}

                # Submit live scans (need crawl results)
                if ctx.target_url:
                    report_svc.add_event("live_scan", "Running AttackBot live scan")
                    tasks["sqli"] = asyncio.to_thread(
                        self._run_sqli, ctx.target_url, ctx.upload_dir, frozen,
                    )
                    report_svc.add_event("xss_scan", "Running XSS attack scan")
                    tasks["xss"] = asyncio.to_thread(
                        self._run_xss, ctx.target_url, ctx.upload_dir, frozen,
                    )
                    report_svc.add_event("cors_scan", "Running CORS misconfiguration scan")
                    tasks["cors"] = asyncio.to_thread(
                        self._run_cors, ctx.target_url, frozen,
                    )
                    report_svc.add_event("ddos_scan", "Running DDoS vulnerability scan")
                    tasks["ddos"] = asyncio.to_thread(
                        self._run_ddos, ctx.target_url, frozen,
                    )
                else:
                    report_svc.add_event("live_scan", "Skipped (no live server)", success=False)
                    report_svc.add_event("xss_scan", "Skipped (no live server)", success=False)
                    report_svc.add_event("cors_scan", "Skipped (no live server)", success=False)
                    report_svc.add_event("ddos_scan", "Skipped (no live server)", success=False)

                # Static scan was already launched — include it
                tasks["static"] = static_task

                keys = list(tasks.keys())
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                return dict(zip(keys, results))

            scan_results = run_sync(_crawl_and_scan())

            # Process results
            for kind, res in scan_results.items():
                if isinstance(res, Exception):
                    logger.warning("[ScanController] %s scan raised: %s", kind, res)
                    report_svc.add_event(kind, f"Error: {res}", success=False)
                    continue

                if kind == "sqli":
                    result = res
                    if result["success"] and result["report"]:
                        report_svc.set_live_scan_report(result["report"])
                        report_svc.add_event(
                            "live_scan",
                            f"Scan complete — {result['endpoints_scanned']} endpoints, "
                            f"{len(result.get('scan_log', []))} payloads sent",
                        )
                        logger.info("[ScanController] Step 5 OK — live scan done")

                        # Run DefendBot on the scan log
                        scan_log = result.get("scan_log", [])
                        if scan_log:
                            try:
                                defend_bot = SQLDefenseBot(target_url=ctx.target_url or "")
                                defend_bot.analyze_scan_log(scan_log)
                                report_svc.set_defense_results(defend_bot.get_results())
                                defense_summary = defend_bot.get_summary()
                                report_svc.add_event(
                                    "defense_sim",
                                    f"Defense simulation complete — {defense_summary.get('attacks_blocked', 0)} blocked, "
                                    f"{defense_summary.get('defense_rate', 0)}% defense rate",
                                )
                                logger.info(
                                    "[ScanController] DefendBot OK — %d analyzed, %d blocked",
                                    defense_summary.get("total_attacks_analyzed", 0),
                                    defense_summary.get("attacks_blocked", 0),
                                )
                            except Exception as exc:
                                logger.warning("[ScanController] DefendBot error: %s", exc)
                                report_svc.add_event("defense_sim", f"Defense error: {exc}", success=False)
                    else:
                        report_svc.add_event("live_scan", f"Scan error: {result.get('error')}", success=False)
                        logger.warning("[ScanController] Step 5 WARN — %s", result.get("error"))

                elif kind == "xss":
                    xss_result = res
                    if xss_result["success"]:
                        report_svc.set_xss_findings(xss_result["findings_dicts"])
                        total_xss = xss_result["summary"]["total_xss_findings"]
                        report_svc.add_event(
                            "xss_scan",
                            f"XSS scan complete — {total_xss} finding(s)",
                        )
                        logger.info("[ScanController] Step 5b OK — XSS scan done (%d findings)", total_xss)

                        # Run XSS DefendBot on the findings
                        xss_findings_dicts = xss_result.get("findings_dicts", [])
                        if xss_findings_dicts:
                            try:
                                xss_defend = XSSDefenseBot(target_url=ctx.target_url or "")
                                xss_defend.analyze_findings(xss_findings_dicts)
                                report_svc.set_xss_defense_results(xss_defend.get_results())
                                xds = xss_defend.get_summary()
                                report_svc.add_event(
                                    "xss_defense_sim",
                                    f"XSS defense simulation complete — {xds.get('total_mitigated', 0)} mitigated, "
                                    f"{xds.get('defense_rate', 0)}% defense rate",
                                )
                                logger.info(
                                    "[ScanController] XSS DefendBot OK — %d evaluated, %d mitigated",
                                    xds.get("total_evaluated", 0),
                                    xds.get("total_mitigated", 0),
                                )
                            except Exception as exc:
                                logger.warning("[ScanController] XSS DefendBot error: %s", exc)
                                report_svc.add_event("xss_defense_sim", f"XSS defense error: {exc}", success=False)
                    else:
                        report_svc.add_event("xss_scan", f"XSS scan error: {xss_result.get('error')}", success=False)
                        logger.warning("[ScanController] Step 5b WARN — %s", xss_result.get("error"))

                elif kind == "static":
                    static_result = res
                    if static_result["success"]:
                        report_svc.set_static_findings(static_result["findings"])
                        report_svc.add_event(
                            "static_scan",
                            f"Found {len(static_result['findings'])} issues in "
                            f"{static_result['files_scanned']} files",
                        )
                        logger.info("[ScanController] Step 6 OK — static scan done")
                    else:
                        report_svc.add_event("static_scan", f"Static error: {static_result['error']}", success=False)

                elif kind == "cors":
                    cors_result = res
                    if cors_result["success"]:
                        report_svc.set_cors_findings(cors_result["findings_dicts"])
                        total_cors = cors_result["summary"]["total_cors_findings"]
                        report_svc.add_event(
                            "cors_scan",
                            f"CORS scan complete — {total_cors} finding(s)",
                        )
                        logger.info("[ScanController] Step 5c OK — CORS scan done (%d findings)", total_cors)

                        # Run CORS DefendBot on the findings
                        cors_findings_dicts = cors_result.get("findings_dicts", [])
                        if cors_findings_dicts:
                            try:
                                cors_defend = CORSDefenseBot(target_url=ctx.target_url or "")
                                cors_defend.analyze_findings(cors_findings_dicts)
                                report_svc.set_cors_defense_results(cors_defend.get_results())
                                cors_ds = cors_defend.get_summary()
                                report_svc.add_event(
                                    "cors_defense_sim",
                                    f"CORS defense simulation complete — {cors_ds.get('attacks_mitigated', 0)} mitigated, "
                                    f"{cors_ds.get('defense_rate', 0)}% defense rate",
                                )
                                logger.info(
                                    "[ScanController] CORS DefendBot OK — %d analyzed, %d mitigated",
                                    cors_ds.get("total_attacks_analyzed", 0),
                                    cors_ds.get("attacks_mitigated", 0),
                                )
                            except Exception as exc:
                                logger.warning("[ScanController] CORS DefendBot error: %s", exc)
                                report_svc.add_event("cors_defense_sim", f"CORS defense error: {exc}", success=False)
                    else:
                        report_svc.add_event("cors_scan", f"CORS scan error: {cors_result.get('error')}", success=False)
                        logger.warning("[ScanController] Step 5c WARN — %s", cors_result.get("error"))

                elif kind == "ddos":
                    ddos_result = res
                    if ddos_result["success"]:
                        report_svc.set_ddos_findings(ddos_result["findings_dicts"])
                        total_ddos = ddos_result["summary"]["total_ddos_findings"]
                        report_svc.add_event(
                            "ddos_scan",
                            f"DDoS scan complete — {total_ddos} finding(s)",
                        )
                        logger.info("[ScanController] Step 5d OK — DDoS scan done (%d findings)", total_ddos)

                        # Run DDoS DefendBot on the findings
                        ddos_findings_dicts = ddos_result.get("findings_dicts", [])
                        if ddos_findings_dicts:
                            try:
                                ddos_defend = DDoSDefenseBot(target_url=ctx.target_url or "")
                                ddos_defend.analyze_findings(ddos_findings_dicts)
                                report_svc.set_ddos_defense_results(ddos_defend.get_results())
                                dds = ddos_defend.get_summary()
                                report_svc.add_event(
                                    "ddos_defense_sim",
                                    f"DDoS defense simulation complete — {dds.get('total_mitigated', 0)} mitigated, "
                                    f"{dds.get('defense_rate', 0)}% defense rate",
                                )
                                logger.info(
                                    "[ScanController] DDoS DefendBot OK — %d evaluated, %d mitigated",
                                    dds.get("total_evaluated", 0),
                                    dds.get("total_mitigated", 0),
                                )
                            except Exception as exc:
                                logger.warning("[ScanController] DDoS DefendBot error: %s", exc)
                                report_svc.add_event("ddos_defense_sim", f"DDoS defense error: {exc}", success=False)
                    else:
                        report_svc.add_event("ddos_scan", f"DDoS scan error: {ddos_result.get('error')}", success=False)
                        logger.warning("[ScanController] Step 5d WARN — %s", ddos_result.get("error"))

            # ── Step 7: Build & save report ───────────────────────────
            report_svc.add_event("report", "Building final report")
            report_dict = report_svc.build()

            report_filename = f"scan_{ctx.upload_id}.json"
            report_path = os.path.join(self.report_dir, report_filename)
            report_svc.save_json(report_path)

            elapsed = time.time() - t0
            report_svc.add_event("report", f"Report saved ({elapsed:.1f}s total)")
            logger.info("[ScanController] Step 7 OK — report → %s (%.1fs)", report_path, elapsed)

            return {
                "success": True,
                "report_path": report_path,
                "report": report_dict,
                "summary": report_svc.summary_text(),
                "error": None,
            }

        except KeyboardInterrupt:
            logger.warning("[ScanController] Interrupted by user")
            report_svc.add_event("error", "Interrupted by user (Ctrl+C)", success=False)
            return self._fail("Scan interrupted by user", report_svc)

        except Exception as exc:
            logger.exception("[ScanController] Pipeline error")
            report_svc.add_event("error", str(exc), success=False)
            return self._fail(str(exc), report_svc)

        finally:
            # ── Step 8: Cleanup ───────────────────────────────────────
            self._cleanup(ctx)

    # ── Cleanup helper ────────────────────────────────────────────────

    def _cleanup(self, ctx: "_PipelineContext") -> None:
        """Stop sandbox and wipe temp dirs."""
        try:
            if ctx.sandbox_id:
                self._sandbox.stop(ctx.sandbox_id)
            elif ctx.sandbox_pid:
                CleanupManager.kill_process(ctx.sandbox_pid)

            if ctx.sandbox_dir:
                CleanupManager.delete_directory(ctx.sandbox_dir)
            if ctx.upload_dir:
                CleanupManager.delete_directory(ctx.upload_dir)

            logger.info("[ScanController] Cleanup complete")
        except Exception as exc:
            logger.warning("[ScanController] Cleanup error: %s", exc)

    # ── Thread-safe scan helpers (called by ThreadPoolExecutor) ───────

    def _run_sqli(self, target_url, upload_dir, crawled_endpoints):
        runner = AttackBotRunner(
            target_url=target_url,
            project_dir=upload_dir,
            config=self._scan_config,
        )
        return runner.run(
            crawled_endpoints=crawled_endpoints if crawled_endpoints else None,
            probe_live=True,
        )

    @staticmethod
    def _run_xss(target_url, upload_dir, crawled_endpoints):
        xr = XSSRunner(target_url=target_url, project_dir=upload_dir)
        return xr.run(
            crawled_endpoints=crawled_endpoints if crawled_endpoints else None,
        )

    @staticmethod
    def _run_static(upload_dir):
        return StaticScanRunner(upload_dir).run()

    @staticmethod
    def _run_cors(target_url, crawled_endpoints):
        cr = CORSRunner(target_url=target_url)
        return cr.run(
            crawled_endpoints=crawled_endpoints if crawled_endpoints else None,
        )

    @staticmethod
    def _run_ddos(target_url, crawled_endpoints):
        dr = DDoSRunner(target_url=target_url)
        return dr.run(
            crawled_endpoints=crawled_endpoints if crawled_endpoints else None,
        )

    # ── Failure helper ────────────────────────────────────────────────

    @staticmethod
    def _fail(msg: str, report_svc: ReportService) -> Dict[str, Any]:
        report_svc.add_event("error", msg, success=False)
        return {
            "success": False,
            "report_path": None,
            "report": report_svc.build() if report_svc else None,
            "summary": "",
            "error": msg,
        }


# ── Internal pipeline state ──────────────────────────────────────────────

class _PipelineContext:
    """Mutable bag of state carried through the pipeline."""

    def __init__(self):
        self.upload_id: str = ""
        self.upload_dir: Optional[str] = None
        self.framework_info: Optional[Dict] = None
        self.sandbox_id: Optional[str] = None
        self.sandbox_pid: Optional[int] = None
        self.sandbox_dir: Optional[str] = None
        self.target_url: Optional[str] = None


# ── CLI entry-point ──────────────────────────────────────────────────────

def main():
    """Quick CLI: ``python scan_controller.py path/to/upload.zip``"""
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description="Prahaar AI — Full Scan Pipeline")
    parser.add_argument("--zip", required=True, help="Path to the ZIP file to scan")
    parser.add_argument("--report-dir", default="reports", help="Report output directory")
    args = parser.parse_args()

    ctrl = ScanController(report_dir=args.report_dir)
    result = ctrl.run(args.zip)

    if result["success"]:
        print(result["summary"])
        print(f"Report saved → {result['report_path']}")
    else:
        print(f"FAILED: {result['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
