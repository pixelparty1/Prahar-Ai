"""
test_scan_pipeline.py
---------------------
End-to-end test for the Prompt 2 scanning & reporting layer.

Creates a sample vulnerable Flask app ZIP, feeds it through
ScanController.run(), and validates the final report.

Run:
    cd backend
    python test_scan_pipeline.py
"""

import json
import logging
import os
import sys
import tempfile
import zipfile

logging.basicConfig(level=logging.INFO, format="%(message)s")

_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from scan_controller import ScanController
from AttackBot.SQL_Injections.sql_injection_scanner import ScanConfig

# ── Step 1: Create a sample vulnerable Flask app ─────────────────────────

SAMPLE_APP = '''\
from flask import Flask, request, g
import sqlite3, os

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), "test.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        c = g.db.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, pass TEXT)")
        c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','secret')")
        g.db.commit()
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

@app.route("/")
def index():
    return "<h1>Test App</h1><a href='/search?q=hello'>Search</a>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # DELIBERATELY VULNERABLE — string interpolation in SQL
    rows = db.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'").fetchall()
    return f"Results: {len(rows)}"

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return """<form method="post" action="/login">
                    <input name="username"><input name="password" type="password">
                    <button type="submit">Login</button></form>"""
    u = request.form.get("username","")
    p = request.form.get("password","")
    db = get_db()
    row = db.execute(f"SELECT * FROM users WHERE name='{u}' AND pass='{p}'").fetchone()
    if row:
        return "Login successful — welcome " + row["name"]
    return "Invalid credentials", 401

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))
'''

def create_test_zip() -> str:
    """Build a ZIP containing the vulnerable Flask app."""
    tmp = tempfile.mkdtemp(prefix="prahaar_test_zip_")
    zip_path = os.path.join(tmp, "vuln_app.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("vuln_app/app.py", SAMPLE_APP)
    print(f"[test] Created test ZIP → {zip_path}")
    return zip_path


# ── Step 2: Run the full pipeline ────────────────────────────────────────

def main():
    zip_path = create_test_zip()

    report_dir = os.path.join(tempfile.gettempdir(), "prahaar_test_reports")
    # Use a fast config: only 2 payloads per category, skip time-based
    fast_config = ScanConfig(
        verbose=False,
        timeout=8.0,
        delay_between_requests=0.02,
        max_payloads_per_category=2,
        skip_time_based=True,
    )
    ctrl = ScanController(report_dir=report_dir, scan_config=fast_config)

    print("\n[test] Running full pipeline …\n")
    result = ctrl.run(zip_path)

    # ── Validate ──────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  PIPELINE RESULT")
    print("═" * 60)
    print(f"  success      : {result['success']}")
    print(f"  error        : {result.get('error')}")
    print(f"  report_path  : {result.get('report_path')}")

    if result["success"] and result.get("report_path"):
        with open(result["report_path"], "r", encoding="utf-8") as fh:
            report = json.load(fh)

        sm = report.get("scan_summary", {})
        vulns = report.get("vulnerabilities", [])
        static = report.get("static_analysis_findings", [])
        crawled = report.get("crawled_endpoints", [])
        events = report.get("pipeline_events", [])

        print(f"  risk level   : {sm.get('overall_risk_level', '?')}")
        print(f"  vulns found  : {len(vulns)}")
        print(f"  static issues: {len(static)}")
        print(f"  endpoints    : {len(crawled)}")
        print(f"  events       : {len(events)}")
        print("═" * 60)

        if result.get("summary"):
            print(result["summary"])

        # Basic assertions
        assert report.get("meta", {}).get("upload_id"), "Missing upload_id"
        assert len(events) > 0, "No pipeline events recorded"
        print("\n[test] ✓ All checks passed!")
    else:
        print(f"\n[test] ✗ Pipeline failed: {result.get('error')}")
        sys.exit(1)

    # Cleanup test zip
    try:
        os.unlink(zip_path)
        os.rmdir(os.path.dirname(zip_path))
    except Exception:
        pass

    print("[test] Done.")


if __name__ == "__main__":
    main()
