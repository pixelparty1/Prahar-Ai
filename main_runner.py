"""main_runner.py — Prahaar AI single entry point

This script is a thin orchestrator that wires together the existing
pipeline modules. It does NOT modify any attack logic.

Run:
    python main_runner.py
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Optional


def _repo_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _backend_dir() -> str:
    root = _repo_root()
    candidate = os.path.join(root, "backend")
    if os.path.isdir(candidate):
        return candidate
    # Fallback: if user runs from within backend/ and moved the script.
    return root


def _ensure_backend_on_path() -> str:
    backend = _backend_dir()
    if backend not in sys.path:
        sys.path.insert(0, backend)
    return backend


def _prompt_non_empty(prompt: str) -> str:
    while True:
        value = input(prompt).strip().strip('"')
        if value:
            return value
        print("Input cannot be empty. Try again.")


def _prompt_choice() -> str:
    print("Select scan type:")
    print("1 - Scan ZIP project")
    print("2 - Scan live website URL")
    print("3 - Scan local project folder")
    print("q - Quit")
    return input("> ").strip().lower()


def _zip_folder(folder_path: str) -> str:
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise FileNotFoundError(f"Folder not found: {folder_path}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_zip = os.path.join(tempfile.gettempdir(), f"prahaar_upload_{ts}.zip")

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(folder_path):
            # Keep zips smaller/cleaner by skipping common junk folders
            dirs[:] = [
                d for d in dirs
                if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}
            ]
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, folder_path)
                zf.write(full, rel)

    return out_zip


def _configure_logging() -> None:
    # Show underlying module progress (ScanController, SandboxManager, etc.)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # requests can be noisy
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _run_zip_pipeline(zip_path: str, report_dir: str) -> int:
    from scan_controller import ScanController

    print("[1/5] Uploading project and detecting framework...")
    print("[2/5] Launching sandbox environment...")
    print("[3/5] Crawling endpoints and scanning (SQLi + XSS + CORS + DDoS in parallel)...")
    print("[4/5] Running static code analysis...")
    print("[5/5] Generating vulnerability report...")

    ctrl = ScanController(report_dir=report_dir)
    result = ctrl.run(zip_path)

    if not result.get("success"):
        print("\nScan failed.")
        print(f"Reason: {result.get('error')}")
        # ScanController already attempts static-only fallback internally.
        if result.get("report"):
            rp = result.get("report_path")
            if rp:
                print(f"Partial report saved at: {rp}")
        return 1

    report_path = result.get("report_path")
    report = result.get("report") or {}
    summary = (report.get("scan_summary") or {})
    total = int(summary.get("total_vulnerabilities", 0)) + int(summary.get("total_xss_vulnerabilities", 0)) + int(summary.get("total_cors_misconfigurations", 0)) + int(summary.get("total_ddos_vulnerabilities", 0))

    live_status = report.get("live_scan_status") or {}
    if live_status and not live_status.get("success", True):
        print("\nSandbox failed to start.")
        if live_status.get("error"):
            print(f"Reason: {live_status['error']}")
        if live_status.get("fallback"):
            print(f"Fallback: {live_status['fallback']}")

    print("\nScan completed.")
    if report_path:
        print("Report saved at:")
        print(report_path)
    print(f"Total vulnerabilities detected: {total}")
    return 0


def _run_live_url_pipeline(target_url: str, report_dir: str) -> int:
    import asyncio
    from crawler import Crawler
    from attackbot_runner import AttackBotRunner
    from xss_runner import XSSRunner
    from cors_runner import CORSRunner
    from ddos_runner import DDoSRunner
    from report_service import ReportService
    from async_engine import run_sync

    target_url = target_url.strip().rstrip("/")

    svc = ReportService(target_url=target_url)
    svc.add_event("start", f"Starting live URL scan: {target_url}")

    print("[1/4] Crawling target for endpoints...")

    # Step 1: Crawl
    crawled_endpoints = []
    try:
        svc.add_event("crawl", f"Crawling {target_url}")
        crawler_obj = Crawler(target_url, max_pages=50, timeout=5.0)
        crawled_endpoints = crawler_obj.crawl()
        svc.set_crawled_endpoints(crawler_obj.get_endpoints_as_dicts())
        svc.add_event("crawl", f"Found {len(crawled_endpoints)} endpoints")
    except Exception as exc:
        msg = f"Crawl failed: {exc}"
        print(msg)
        svc.add_event("crawl", msg, success=False)

    # Freeze an immutable snapshot — all modules scan the exact same list
    frozen_endpoints = tuple(crawled_endpoints)

    # Steps 2-3: Run SQLi, XSS, CORS scans in parallel via asyncio.gather
    print(f"[2/4] Scanning {len(frozen_endpoints)} endpoints (SQLi + XSS + CORS + DDoS in parallel)...")
    svc.add_event("live_scan", "Running SQL injection scan")
    svc.add_event("xss_scan", "Running XSS scan")
    svc.add_event("cors_scan", "Running CORS scan")
    svc.add_event("ddos_scan", "Running DDoS scan")

    def _sqli_task():
        runner = AttackBotRunner(target_url=target_url, project_dir=None)
        return runner.run(
            crawled_endpoints=list(frozen_endpoints) if frozen_endpoints else None,
            probe_live=True,
        )

    def _xss_task():
        xr = XSSRunner(target_url=target_url, project_dir=None)
        return xr.run(
            crawled_endpoints=list(frozen_endpoints) if frozen_endpoints else None,
        )

    def _cors_task():
        cr = CORSRunner(target_url=target_url)
        return cr.run(
            crawled_endpoints=list(frozen_endpoints) if frozen_endpoints else None,
        )

    def _ddos_task():
        dr = DDoSRunner(target_url=target_url)
        return dr.run(
            crawled_endpoints=list(frozen_endpoints) if frozen_endpoints else None,
        )

    async def _run_all():
        return await asyncio.gather(
            asyncio.to_thread(_sqli_task),
            asyncio.to_thread(_xss_task),
            asyncio.to_thread(_cors_task),
            asyncio.to_thread(_ddos_task),
            return_exceptions=True,
        )

    sqli_res, xss_res, cors_res, ddos_res = run_sync(_run_all())

    # Collect SQLi result
    if isinstance(sqli_res, Exception):
        msg = f"SQL injection scan failed: {sqli_res}"
        print(msg)
        svc.add_event("live_scan", msg, success=False)
    else:
        runner_result = sqli_res
        if runner_result.get("success") and runner_result.get("report") is not None:
            svc.set_live_scan_report(runner_result["report"])
            svc.add_event(
                "live_scan",
                f"SQL scan complete — {runner_result.get('endpoints_scanned', 0)} endpoints scanned",
            )
        else:
            err = runner_result.get("error") or "Unknown SQL scan error"
            print(f"SQL injection scan error: {err}")
            svc.add_event("live_scan", f"SQL scan error: {err}", success=False)

    # Collect XSS result
    if isinstance(xss_res, Exception):
        msg = f"XSS scan failed: {xss_res}"
        print(msg)
        svc.add_event("xss_scan", msg, success=False)
    else:
        xss_result = xss_res
        if xss_result.get("success"):
            svc.set_xss_findings(xss_result.get("findings_dicts") or [])
            total_xss = (xss_result.get("summary") or {}).get("total_xss_findings", 0)
            svc.add_event("xss_scan", f"XSS scan complete — {total_xss} finding(s)")
        else:
            err = xss_result.get("error") or "Unknown XSS scan error"
            print(f"XSS scan error: {err}")
            svc.add_event("xss_scan", f"XSS scan error: {err}", success=False)

    # Collect CORS result
    if isinstance(cors_res, Exception):
        msg = f"CORS scan failed: {cors_res}"
        print(msg)
        svc.add_event("cors_scan", msg, success=False)
    else:
        cors_result = cors_res
        if cors_result.get("success"):
            svc.set_cors_findings(cors_result.get("findings_dicts") or [])
            total_cors = (cors_result.get("summary") or {}).get("total_cors_findings", 0)
            svc.add_event("cors_scan", f"CORS scan complete — {total_cors} finding(s)")
        else:
            err = cors_result.get("error") or "Unknown CORS scan error"
            print(f"CORS scan error: {err}")
            svc.add_event("cors_scan", f"CORS scan error: {err}", success=False)

    # Collect DDoS result
    if isinstance(ddos_res, Exception):
        msg = f"DDoS scan failed: {ddos_res}"
        print(msg)
        svc.add_event("ddos_scan", msg, success=False)
    else:
        ddos_result = ddos_res
        if ddos_result.get("success"):
            svc.set_ddos_findings(ddos_result.get("findings_dicts") or [])
            total_ddos = (ddos_result.get("summary") or {}).get("total_ddos_findings", 0)
            svc.add_event("ddos_scan", f"DDoS scan complete — {total_ddos} finding(s)")
        else:
            err = ddos_result.get("error") or "Unknown DDoS scan error"
            print(f"DDoS scan error: {err}")
            svc.add_event("ddos_scan", f"DDoS scan error: {err}", success=False)

    # Step 3: Static scan not available (no project source)
    svc.add_event("static_scan", "Skipped (no project source for static analysis)", success=False)

    # Step 4: Build & save report
    print("[3/4] Static analysis skipped (no project source).")
    print("[4/4] Generating vulnerability report...")
    report = svc.build()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"scan_live_{ts}.json")
    svc.save_json(report_path)

    summary = report.get("scan_summary") or {}
    total = (
        int(summary.get("total_vulnerabilities", 0))
        + int(summary.get("total_xss_vulnerabilities", 0))
        + int(summary.get("total_cors_misconfigurations", 0))
        + int(summary.get("total_ddos_vulnerabilities", 0))
    )

    print("\nScan completed.")
    print("Report saved at:")
    print(report_path)
    print(f"Total vulnerabilities detected: {total}")
    return 0


def main() -> int:
    backend = _ensure_backend_on_path()
    _configure_logging()

    report_dir = os.path.join(backend, "reports")
    os.makedirs(report_dir, exist_ok=True)

    try:
        choice = _prompt_choice()

        if choice in {"q", "quit", "exit"}:
            return 0

        if choice == "1":
            zip_path = _prompt_non_empty("Enter path to ZIP file: ")
            zip_path = os.path.abspath(zip_path)
            if not os.path.isfile(zip_path):
                print(f"File not found: {zip_path}")
                return 1
            return _run_zip_pipeline(zip_path, report_dir)

        if choice == "2":
            url = _prompt_non_empty("Enter target website URL: ")
            return _run_live_url_pipeline(url, report_dir)

        if choice == "3":
            folder = _prompt_non_empty("Enter project folder path: ")
            folder = os.path.abspath(folder)
            if not os.path.isdir(folder):
                print(f"Folder not found: {folder}")
                return 1

            tmp_zip: Optional[str] = None
            try:
                print("Preparing local folder (zipping)...")
                tmp_zip = _zip_folder(folder)
                return _run_zip_pipeline(tmp_zip, report_dir)
            finally:
                if tmp_zip and os.path.isfile(tmp_zip):
                    try:
                        os.remove(tmp_zip)
                    except Exception:
                        pass

        print("Invalid choice. Please select 1, 2, 3, or q.")
        return 1

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130

    except Exception as exc:
        print("\nUnexpected error.")
        print(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
