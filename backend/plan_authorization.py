# backend/plan_authorization.py
import sqlite3

# Plan permission config
plan_permissions = {
    "free":    {"attackbot": True,  "defendbot": False, "narratorbot": False, "scan_limit": 1},
    "starter": {"attackbot": True,  "defendbot": False, "narratorbot": False, "scan_limit": "weekly"},
    "pro":     {"attackbot": True,  "defendbot": True,  "narratorbot": True,  "scan_limit": "unlimited"},
}

def get_user_plan(user_id, db_path="../db.sqlite3"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT plans FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "free"

def get_user_scan_count(user_id, db_path="../db.sqlite3"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
    count = cur.fetchone()[0]
    conn.close()
    return count

def check_plan_permissions(user_id, db_path="../db.sqlite3"):
    plan = get_user_plan(user_id, db_path)
    perms = plan_permissions.get(plan, plan_permissions["free"])
    # Free plan: enforce scan limit
    if plan == "free" and get_user_scan_count(user_id, db_path) >= perms["scan_limit"]:
        return None, "Free plan limit reached. Upgrade your plan to scan additional websites."
    return perms, None
