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
from static_scan_runner import StaticScanRunner
from report_service import ReportService
from cleanup_manager import CleanupManager
from AttackBot.SQL_Injections.sql_injection_scanner import ScanConfig

logger = logging.getLogger(__name__)


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
                logger.info("[ScanController] Step 3 OK — %s (PID %s)", ctx.target_url, ctx.sandbox_pid)
            else:
                report_svc.add_event("sandbox", f"Sandbox failed: {sb['error']}", success=False)
                logger.warning("[ScanController] Step 3 WARN — sandbox failed: %s (will do static-only scan)", sb["error"])

            # ── Step 4: Crawl (if sandbox is up) ──────────────────────
            crawled_endpoints = []
            if ctx.target_url:
                report_svc.add_event("crawl", f"Crawling {ctx.target_url}")
                try:
                    cr = Crawler(ctx.target_url, max_pages=50, timeout=5.0)
                    crawled_endpoints = cr.crawl()
                    report_svc.set_crawled_endpoints(cr.get_endpoints_as_dicts())
                    report_svc.add_event("crawl", f"Found {len(crawled_endpoints)} endpoints")
                    logger.info("[ScanController] Step 4 OK — %d endpoints crawled", len(crawled_endpoints))
                except Exception as exc:
                    report_svc.add_event("crawl", f"Crawl error: {exc}", success=False)
                    logger.warning("[ScanController] Step 4 WARN — crawl error: %s", exc)
            else:
                report_svc.add_event("crawl", "Skipped (no live server)", success=False)

            # ── Step 5: Live scan (if sandbox is up) ──────────────────
            if ctx.target_url:
                report_svc.add_event("live_scan", "Running AttackBot live scan")
                runner = AttackBotRunner(
                    target_url=ctx.target_url,
                    project_dir=ctx.upload_dir,
                    config=self._scan_config,
                )
                result = runner.run(
                    crawled_endpoints=crawled_endpoints if crawled_endpoints else None,
                    probe_live=True,
                )
                if result["success"] and result["report"]:
                    report_svc.set_live_scan_report(result["report"])
                    report_svc.add_event(
                        "live_scan",
                        f"Scan complete — {result['endpoints_scanned']} endpoints, "
                        f"{len(result.get('scan_log', []))} payloads sent",
                    )
                    logger.info("[ScanController] Step 5 OK — live scan done")
                else:
                    report_svc.add_event("live_scan", f"Scan error: {result.get('error')}", success=False)
                    logger.warning("[ScanController] Step 5 WARN — %s", result.get("error"))
            else:
                report_svc.add_event("live_scan", "Skipped (no live server)", success=False)

            # ── Step 6: Static scan (always runs) ─────────────────────
            report_svc.add_event("static_scan", "Running static code analysis")
            static_runner = StaticScanRunner(ctx.upload_dir)
            static_result = static_runner.run()
            if static_result["success"]:
                report_svc.set_static_findings(static_result["findings"])
                report_svc.add_event(
                    "static_scan",
                    f"Found {len(static_result['findings'])} issues in {static_result['files_scanned']} files",
                )
                logger.info("[ScanController] Step 6 OK — static scan done")
            else:
                report_svc.add_event("static_scan", f"Static error: {static_result['error']}", success=False)

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
