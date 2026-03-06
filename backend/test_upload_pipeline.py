"""
test_upload_pipeline.py
-----------------------
End-to-end test of the upload → extract → detect → launch pipeline.

Creates a tiny sample Flask project as a ZIP, feeds it through the
full infrastructure, and prints confirmation at every step.

Usage:
    cd backend
    python test_upload_pipeline.py
"""

import os
import sys
import time
import zipfile
import tempfile

# Ensure backend/ is on the import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from upload_handler import UploadHandler
from framework_detector import FrameworkDetector
from sandbox_manager import SandboxManager
from cleanup_manager import CleanupManager

SEP = "=" * 60


def create_sample_flask_zip() -> str:
    """
    Generate a minimal Flask app inside a ZIP file and return its path.
    The app has one deliberately vulnerable endpoint for later scanning.
    """
    zip_path = os.path.join(tempfile.gettempdir(), "sample_flask_project.zip")

    app_code = '''\
from flask import Flask, request, jsonify
import sqlite3, os

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), "test.db")

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT
        );
        INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin');
        INSERT OR IGNORE INTO users VALUES (2,'user1','pass1','user');
    """)
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return "Sample Flask App Running!", 200

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB)
    # VULNERABLE: string interpolation in SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        row = conn.execute(query).fetchone()
        if row:
            return f"Login OK — welcome {row[1]}!", 200
        return "Invalid credentials", 401
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    query = f"SELECT username FROM users WHERE username LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
        return jsonify([r[0] for r in rows])
    except Exception as e:
        return f"SQL error: {e}", 500

if __name__ == "__main__":
    init_db()
    import os as _os
    port = int(_os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
'''

    requirements = "flask\n"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sample_project/app.py", app_code)
        zf.writestr("sample_project/requirements.txt", requirements)

    print(f"[Test] Sample ZIP created: {zip_path}")
    return zip_path


def main():
    print(SEP)
    print("  PRAHAAR AI — Upload Pipeline Test")
    print(SEP)

    # ── Step 1: Create sample ZIP ─────────────────────────────────────
    print("\n[Step 1] Creating sample Flask project ZIP …")
    zip_path = create_sample_flask_zip()

    # ── Step 2: Upload & extract ──────────────────────────────────────
    print("\n[Step 2] Uploading and extracting …")
    uploader = UploadHandler()
    result = uploader.handle_zip(zip_path)

    if not result["success"]:
        print(f"  ✗ Upload failed: {result['error']}")
        return
    project_dir = result["project_dir"]
    upload_id = result["upload_id"]
    print(f"  ✓ Project extracted to:\n    {project_dir}")

    # ── Step 3: Detect framework ──────────────────────────────────────
    print("\n[Step 3] Detecting framework …")
    detector = FrameworkDetector()
    fw_info = detector.detect(project_dir)

    print(f"  ✓ Framework detected: {fw_info['framework']}")
    print(f"    Entry point : {fw_info['entry_point']}")
    print(f"    Start cmd   : {fw_info['start_command']}")
    print(f"    Indicators  : {fw_info['indicators']}")

    # ── Step 4: Launch sandbox ────────────────────────────────────────
    print("\n[Step 4] Launching sandbox server …")
    sandbox = SandboxManager()
    launch = sandbox.launch(project_dir, framework_info=fw_info)

    if not launch["success"]:
        print(f"  ✗ Sandbox failed: {launch['error']}")
        # Cleanup upload dir
        CleanupManager.delete_directory(project_dir)
        return

    target_url = launch["target_url"]
    sandbox_id = launch["sandbox_id"]
    pid = launch["process_id"]

    print(f"  ✓ Sandbox running at:")
    print(f"    {target_url}")
    print(f"    PID: {pid}")

    # ── Step 5: Quick health check ────────────────────────────────────
    print("\n[Step 5] Health-checking the server …")
    try:
        import requests
        resp = requests.get(target_url, timeout=5)
        print(f"  ✓ GET / → {resp.status_code}  body={resp.text[:80]}")
    except Exception as exc:
        print(f"  ✗ Health check failed: {exc}")

    # ── Step 6: Cleanup ───────────────────────────────────────────────
    print("\n[Step 6] Cleaning up …")
    inst = sandbox.get_instance(sandbox_id)
    sandbox_dir = inst.sandbox_dir if inst else None

    cleanup = CleanupManager.full_cleanup(
        pid=pid,
        sandbox_dir=sandbox_dir,
        upload_dir=project_dir,
    )
    print(f"  Process killed : {cleanup['process_killed']}")
    print(f"  Sandbox deleted: {cleanup['sandbox_deleted']}")
    print(f"  Upload deleted : {cleanup['upload_deleted']}")

    # ── Done ──────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  Pipeline test PASSED — infrastructure is ready.")
    print(f"  The AttackBot can later scan: {target_url}")
    print(SEP)


if __name__ == "__main__":
    main()
