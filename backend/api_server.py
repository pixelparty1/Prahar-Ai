"""api_server.py — Flask HTTP API wrapping the existing Prahaar scan pipeline.

Exposes REST endpoints consumed by the Express proxy layer so the
frontend can trigger scans, check status, and retrieve reports without
touching any existing pipeline logic.

Run:
    python api_server.py          # listens on 0.0.0.0:8000
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional


from flask import Flask, jsonify, request, Response
from plan_authorization import check_plan_permissions

# ── Path setup ────────────────────────────────────────────────────────────
_BACKEND = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_BACKEND)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

REPORT_DIR = os.path.join(_BACKEND, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "prahaar_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger("api_server")

# ── In-memory scan state ──────────────────────────────────────────────────
_scans: Dict[str, Dict[str, Any]] = {}
_scans_lock = threading.Lock()

app = Flask(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────

def _new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def _set_scan(scan_id: str, data: Dict[str, Any]) -> None:
    with _scans_lock:
        _scans[scan_id] = data


def _get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with _scans_lock:
        return _scans.get(scan_id)


def _update_scan(scan_id: str, **fields: Any) -> None:
    with _scans_lock:
        if scan_id in _scans:
            _scans[scan_id].update(fields)


# ── Background workers ────────────────────────────────────────────────────

def _run_zip_scan(scan_id: str, zip_path: str) -> None:
    """Run the ScanController pipeline in a background thread."""
    try:
        _update_scan(scan_id, status="running", phase="Uploading & detecting framework")
        from scan_controller import ScanController

        ctrl = ScanController(report_dir=REPORT_DIR)
        result = ctrl.run(zip_path)

        if result.get("success"):
            _update_scan(
                scan_id,
                status="completed",
                phase="Completed",
                report=result.get("report"),
                report_path=result.get("report_path"),
            )
        else:
            _update_scan(
                scan_id,
                status="failed",
                phase="Failed",
                error=result.get("error", "Scan failed"),
                report=result.get("report"),
                report_path=result.get("report_path"),
            )
    except Exception as exc:
        logger.exception("ZIP scan %s failed", scan_id)
        _update_scan(scan_id, status="failed", phase="Failed", error=str(exc))
    finally:
        # Clean up temp zip
        try:
            if os.path.isfile(zip_path):
                os.remove(zip_path)
        except OSError:
            pass


def _run_url_scan(scan_id: str, target_url: str, mode: str) -> None:
    """Run the live-URL pipeline in a background thread.

    mode:
        'attack'   → _run_live_url_pipeline (attack only)
        'full'     → _run_orchestrated_pipeline (attack + defense + narrator)
    """
    try:
        _update_scan(scan_id, status="running", phase="Crawling target")

        # Import pipeline functions from main_runner
        sys.path.insert(0, _ROOT)
        from main_runner import _run_live_url_pipeline, _run_orchestrated_pipeline, _ensure_backend_on_path

        _ensure_backend_on_path()

        if mode == "full":
            _update_scan(scan_id, phase="Attack + Defense simulation")
            exit_code = _run_orchestrated_pipeline(target_url, REPORT_DIR)
        else:
            _update_scan(scan_id, phase="Scanning endpoints")
            exit_code = _run_live_url_pipeline(target_url, REPORT_DIR)

        # Find the most recent report file
        report_files = sorted(
            [f for f in os.listdir(REPORT_DIR) if f.endswith(".json")],
            key=lambda f: os.path.getmtime(os.path.join(REPORT_DIR, f)),
            reverse=True,
        )

        report_path = os.path.join(REPORT_DIR, report_files[0]) if report_files else None
        report_data = None
        if report_path and os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as fh:
                report_data = json.load(fh)

        if exit_code == 0:
            _update_scan(
                scan_id,
                status="completed",
                phase="Completed",
                report=report_data,
                report_path=report_path,
            )
        else:
            _update_scan(
                scan_id,
                status="failed",
                phase="Failed",
                error="Scan exited with non-zero code",
                report=report_data,
                report_path=report_path,
            )
    except Exception as exc:
        logger.exception("URL scan %s failed", scan_id)
        _update_scan(scan_id, status="failed", phase="Failed", error=str(exc))


def _run_folder_scan(scan_id: str, folder_path: str) -> None:
    """Zip a local folder and run the ZIP pipeline."""
    try:
        _update_scan(scan_id, status="running", phase="Zipping folder")
        sys.path.insert(0, _ROOT)
        from main_runner import _zip_folder

        zip_path = _zip_folder(folder_path)
        _run_zip_scan(scan_id, zip_path)
    except Exception as exc:
        logger.exception("Folder scan %s failed", scan_id)
        _update_scan(scan_id, status="failed", phase="Failed", error=str(exc))


# ══════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════

# ── Health ────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "prahaar-api"})


# ── Run (used by /api/command/run proxy) ──────────────────────────────────

@app.route("/run", methods=["POST"])
def run_simulation():
    """Start a scan triggered from the Command Center."""
    body = request.get_json(silent=True) or {}
    target_url = (body.get("targetUrl") or "").strip()
    selected_bot = body.get("selectedBotId") or ""

    if not target_url:
        return jsonify({"success": False, "message": "targetUrl is required"}), 400

    scan_id = _new_scan_id()

    # Determine scan mode based on selected bot
    if selected_bot in ("bot-3",):
        # NarratorBot selected → full orchestrated pipeline
        mode = "full"
    elif selected_bot in ("bot-2",):
        # DefendBot selected → full pipeline
        mode = "full"
    else:
        # AttackBot / SpyBot / TrapBot → attack-only
        mode = "attack"

    _set_scan(scan_id, {
        "scan_id": scan_id,
        "type": "url",
        "target": target_url,
        "mode": mode,
        "bot": selected_bot,
        "status": "queued",
        "phase": "Queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report": None,
        "report_path": None,
        "error": None,
    })

    thread = threading.Thread(target=_run_url_scan, args=(scan_id, target_url, mode), daemon=True)
    thread.start()

    return jsonify({
        "success": True,
        "simulationId": scan_id,
        "message": f"Scan started on {target_url}",
    })


# ── Stop ──────────────────────────────────────────────────────────────────

@app.route("/stop", methods=["POST"])
def stop_simulation():
    body = request.get_json(silent=True) or {}
    scan_id = body.get("simulationId")
    if scan_id:
        _update_scan(scan_id, status="stopped", phase="Stopped by user")
    return jsonify({"success": True, "message": "Simulation stopped"})


# ── Status ────────────────────────────────────────────────────────────────

@app.route("/status", methods=["GET"])
def get_status():
    """Return status of the most recent scan, or a specific scan_id."""
    scan_id = request.args.get("scan_id")

    if scan_id:
        scan = _get_scan(scan_id)
        if not scan:
            return jsonify({"active": False, "message": "Scan not found"}), 404
        return jsonify({
            "active": scan["status"] == "running",
            "simulationId": scan["scan_id"],
            "status": scan["status"],
            "phase": scan["phase"],
            "error": scan.get("error"),
        })

    # Return the latest scan
    with _scans_lock:
        if not _scans:
            return jsonify({"active": False, "message": "No scans running"})
        latest = max(_scans.values(), key=lambda s: s.get("created_at", ""))

    return jsonify({
        "active": latest["status"] == "running",
        "simulationId": latest["scan_id"],
        "status": latest["status"],
        "phase": latest["phase"],
        "error": latest.get("error"),
    })


# ── Reports ───────────────────────────────────────────────────────────────

@app.route("/reports", methods=["GET"])
def list_reports():
    """List all saved JSON reports."""
    reports = []
    for fname in sorted(os.listdir(REPORT_DIR), reverse=True):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(REPORT_DIR, fname)
        reports.append({
            "filename": fname,
            "size": os.path.getsize(fpath),
            "modified": datetime.fromtimestamp(
                os.path.getmtime(fpath), tz=timezone.utc
            ).isoformat(),
        })
    return jsonify({"reports": reports})


@app.route("/reports/<filename>", methods=["GET"])
def get_report(filename: str):
    """Return a specific report JSON."""
    # Sanitize filename
    safe_name = os.path.basename(filename)
    fpath = os.path.join(REPORT_DIR, safe_name)
    if not os.path.isfile(fpath):
        return jsonify({"error": "Report not found"}), 404
    with open(fpath, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return jsonify(data)


# ── ZIP Upload Scan ───────────────────────────────────────────────────────

@app.route("/scan/upload", methods=["POST"])
def scan_upload():
    """Accept a ZIP file upload and start a scan."""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename or not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"success": False, "error": "Only .zip files are accepted"}), 400


    # --- PLAN AUTHORIZATION ---
    # TODO: Replace with actual user_id from session/auth context
    user_id = request.headers.get("X-User-Id") or request.form.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "User authentication required."}), 401
    perms, error = check_plan_permissions(user_id)
    if error:
        return jsonify({"success": False, "error": error}), 403
    if not perms["attackbot"]:
        return jsonify({"success": False, "error": "Your plan does not allow attack simulation."}), 403

    scan_id = _new_scan_id()
    zip_path = os.path.join(UPLOAD_DIR, f"upload_{scan_id}.zip")
    uploaded.save(zip_path)

    _set_scan(scan_id, {
        "scan_id": scan_id,
        "type": "zip",
        "target": uploaded.filename,
        "mode": "zip",
        "status": "queued",
        "phase": "Queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report": None,
        "report_path": None,
        "error": None,
    })

    thread = threading.Thread(target=_run_zip_scan, args=(scan_id, zip_path), daemon=True)
    thread.start()

    return jsonify({
        "success": True,
        "scanId": scan_id,
        "message": f"Scan started for {uploaded.filename}",
    })


# ── URL Link Scan ─────────────────────────────────────────────────────────

@app.route("/scan/link", methods=["POST"])
def scan_link():
    """Accept a URL and start a live scan."""
    body = request.get_json(silent=True) or {}
    target_url = (body.get("url") or "").strip()
    mode = body.get("mode", "attack")  # "attack" or "full"

    if not target_url:
        return jsonify({"success": False, "error": "url is required"}), 400


    # --- PLAN AUTHORIZATION ---
    user_id = request.headers.get("X-User-Id") or body.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "User authentication required."}), 401
    perms, error = check_plan_permissions(user_id)
    if error:
        return jsonify({"success": False, "error": error}), 403
    if not perms["attackbot"]:
        return jsonify({"success": False, "error": "Your plan does not allow attack simulation."}), 403

    scan_id = _new_scan_id()

    _set_scan(scan_id, {
        "scan_id": scan_id,
        "type": "url",
        "target": target_url,
        "mode": mode,
        "status": "queued",
        "phase": "Queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report": None,
        "report_path": None,
        "error": None,
    })

    thread = threading.Thread(target=_run_url_scan, args=(scan_id, target_url, mode), daemon=True)
    thread.start()

    return jsonify({
        "success": True,
        "scanId": scan_id,
        "message": f"Scan started on {target_url}",
    })


# ── Folder Scan ───────────────────────────────────────────────────────────

@app.route("/scan/folder", methods=["POST"])
def scan_folder():
    """Accept a local folder path and start a scan."""
    body = request.get_json(silent=True) or {}
    folder_path = (body.get("path") or "").strip()

    if not folder_path or not os.path.isdir(folder_path):
        return jsonify({"success": False, "error": "Valid folder path is required"}), 400

    scan_id = _new_scan_id()

    _set_scan(scan_id, {
        "scan_id": scan_id,
        "type": "folder",
        "target": folder_path,
        "mode": "zip",
        "status": "queued",
        "phase": "Queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report": None,
        "report_path": None,
        "error": None,
    })

    thread = threading.Thread(target=_run_folder_scan, args=(scan_id, folder_path), daemon=True)
    thread.start()

    return jsonify({
        "success": True,
        "scanId": scan_id,
        "message": f"Scan started for folder {folder_path}",
    })


# ── Scan Status ───────────────────────────────────────────────────────────

@app.route("/scan/status/<scan_id>", methods=["GET"])
def scan_status(scan_id: str):
    """Get the status of a particular scan."""

    # --- PLAN AUTHORIZATION ---
    user_id = request.headers.get("X-User-Id") or body.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "User authentication required."}), 401
    perms, error = check_plan_permissions(user_id)
    if error:
        return jsonify({"success": False, "error": error}), 403
    if not perms["attackbot"]:
        return jsonify({"success": False, "error": "Your plan does not allow attack simulation."}), 403

    scan_id = _new_scan_id()

    # Determine scan mode based on selected bot
    if selected_bot in ("bot-3",):
        # NarratorBot selected → full orchestrated pipeline
        mode = "full"
    elif selected_bot in ("bot-2",):
        # DefendBot selected → full pipeline
        mode = "full"
    else:
        # AttackBot / SpyBot / TrapBot → attack-only
        mode = "attack"

    _set_scan(scan_id, {
        "scan_id": scan_id,
        "type": "url",
        "target": target_url,
        "mode": mode,
        "bot": selected_bot,
        "status": "queued",
        "phase": "Queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report": None,
        "report_path": None,
        "error": None,
    })

    thread = threading.Thread(target=_run_url_scan, args=(scan_id, target_url, mode), daemon=True)
    thread.start()

    return jsonify({
        "success": True,
        "simulationId": scan_id,
        "message": f"Scan started on {target_url}",
    })


# ── Stream (SSE placeholder) ─────────────────────────────────────────────

@app.route("/stream", methods=["GET"])
def stream():
    """SSE endpoint placeholder for real-time scan events."""
    def generate():
        yield "data: {\"type\": \"connected\"}\n\n"
    return Response(generate(), mimetype="text/event-stream")


# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PYTHON_API_PORT", "8000"))
    logger.info("Starting Prahaar API server on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
