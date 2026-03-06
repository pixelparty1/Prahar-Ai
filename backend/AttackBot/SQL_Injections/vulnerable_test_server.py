"""
vulnerable_test_server.py
-------------------------
A deliberately vulnerable Flask application for testing the
SQLInjectionAttackBot.

**WARNING**: This server is intentionally insecure. It must ONLY be
run locally for testing purposes. NEVER expose it to the internet.

Endpoints
---------
  POST /login           – vulnerable login form (authentication bypass)
  GET  /search?q=       – vulnerable search (union injection, data extraction)
  GET  /api/user?id=    – vulnerable user lookup
  GET  /product?item=   – vulnerable product lookup
  POST /comment         – vulnerable comment insert

Database
--------
SQLite in-memory database with tables:
  • users   (id, username, password, role)
  • products(id, name, price)
  • comments(id, user, text)
"""

from __future__ import annotations

import sqlite3
import os
from flask import Flask, request, g, jsonify

app = Flask(__name__)

DATABASE = os.path.join(os.path.dirname(__file__), "test_users.db")


# ── Database helpers ──────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed data."""
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS comments;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT NOT NULL,
            price REAL NOT NULL
        );

        CREATE TABLE comments (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            text TEXT NOT NULL
        );

        INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin');
        INSERT INTO users (username, password, role) VALUES ('user1', 'password1', 'user');
        INSERT INTO users (username, password, role) VALUES ('user2', 'password2', 'user');

        INSERT INTO products (name, price) VALUES ('Laptop', 999.99);
        INSERT INTO products (name, price) VALUES ('Phone', 699.99);
        INSERT INTO products (name, price) VALUES ('Tablet', 399.99);

        INSERT INTO comments (user, text) VALUES ('user1', 'Great product!');
        INSERT INTO comments (user, text) VALUES ('user2', 'Works as expected.');
    """)

    conn.commit()
    conn.close()


# ── VULNERABLE Endpoints (intentionally insecure) ────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """
    Vulnerable login – uses string formatting in SQL query.
    Susceptible to authentication bypass.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    # ⚠ VULNERABLE: direct string interpolation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        result = db.execute(query).fetchone()
        if result:
            return f"Login successful. Welcome, {result['username']}! Role: {result['role']}", 200
        else:
            return "Invalid credentials", 401
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route("/search", methods=["GET"])
def search():
    """
    Vulnerable search – UNION injection possible.
    """
    q = request.args.get("q", "")

    db = get_db()
    # ⚠ VULNERABLE: direct string interpolation
    query = f"SELECT name, price FROM products WHERE name LIKE '%{q}%'"

    try:
        rows = db.execute(query).fetchall()
        results = [{"name": r[0], "price": r[1]} for r in rows]
        return jsonify(results), 200
    except Exception as e:
        return f"SQL error: {str(e)}", 500


@app.route("/api/user", methods=["GET"])
def get_user():
    """
    Vulnerable user lookup by ID.
    """
    user_id = request.args.get("id", "")

    db = get_db()
    # ⚠ VULNERABLE: direct string interpolation
    query = f"SELECT id, username, role FROM users WHERE id={user_id}"

    try:
        result = db.execute(query).fetchone()
        if result:
            return jsonify({"id": result[0], "username": result[1], "role": result[2]}), 200
        else:
            return "User not found", 404
    except Exception as e:
        return f"SQL error: {str(e)}", 500


@app.route("/product", methods=["GET"])
def get_product():
    """
    Vulnerable product lookup.
    """
    item = request.args.get("item", "")

    db = get_db()
    # ⚠ VULNERABLE
    query = f"SELECT * FROM products WHERE name='{item}'"

    try:
        result = db.execute(query).fetchone()
        if result:
            return jsonify({"id": result[0], "name": result[1], "price": result[2]}), 200
        else:
            return "Product not found", 404
    except Exception as e:
        return f"SQL error: {str(e)}", 500


@app.route("/comment", methods=["POST"])
def add_comment():
    """
    Vulnerable comment insertion.
    """
    user = request.form.get("user", "")
    text = request.form.get("text", "")

    db = get_db()
    # ⚠ VULNERABLE
    query = f"INSERT INTO comments (user, text) VALUES ('{user}', '{text}')"

    try:
        db.execute(query)
        db.commit()
        return "Comment added", 200
    except Exception as e:
        return f"SQL error: {str(e)}", 500


# ── Health-check (safe) ──────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return "Vulnerable Test Server is running. For testing only!", 200


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[*] Initializing test database...")
    init_db()
    print("[*] Starting vulnerable test server on http://127.0.0.1:5000")
    print("[!] WARNING: This server is intentionally insecure. For testing only!")
    app.run(host="127.0.0.1", port=5000, debug=False)
