"""
run_attack_bot.py
-----------------
CLI runner script to launch the SQLInjectionAttackBot against the
included vulnerable test server (or any other target).

Usage
-----
  # 1. Start the vulnerable test server (in a separate terminal):
  #    python -m AttackBot.vulnerable_test_server
  #
  # 2. Run the scanner:
  #    python -m AttackBot.run_attack_bot

  Or run directly:
      python run_attack_bot.py
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

# Ensure parent directory is on path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from AttackBot.SQL_Injections.sql_injection_scanner import SQLInjectionAttackBot, ScanConfig
from AttackBot.SQL_Injections.endpoint_finder import DiscoveredEndpoint


def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection AttackBot – Vulnerability Scanner",
    )
    parser.add_argument(
        "--target", "-t",
        default="http://127.0.0.1:5000",
        help="Base URL of the target web application (default: http://127.0.0.1:5000)",
    )
    parser.add_argument(
        "--project-dir", "-d",
        default=None,
        help="Path to uploaded project source code for static analysis.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="File path to save the JSON report.",
    )
    parser.add_argument(
        "--skip-time-based",
        action="store_true",
        help="Skip time-based blind injection tests (faster scan).",
    )
    parser.add_argument(
        "--skip-destructive",
        action="store_true",
        help="Skip destructive-simulation payloads (UPDATE/DELETE/DROP).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress verbose console output.",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Only perform static source-code analysis (no live server needed).",
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO if not args.quiet else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config = ScanConfig(
        skip_time_based=args.skip_time_based,
        skip_destructive_sim=args.skip_destructive,
        verbose=not args.quiet,
    )

    bot = SQLInjectionAttackBot(target_url=args.target, config=config)

    # ── Static-only mode ──────────────────────────────────────────────
    if args.static_only:
        if not args.project_dir:
            # Default to scanning the AttackBot directory itself (for the vuln server)
            args.project_dir = os.path.dirname(os.path.abspath(__file__))
        report = bot.static_scan(args.project_dir)
        if args.output:
            bot.save_report(args.output)
        else:
            report.print_report()
        return

    # ── Live scan mode ────────────────────────────────────────────────

    # Define known endpoints for the built-in test server
    test_endpoints = [
        DiscoveredEndpoint(path="/login", method="POST", parameters=["username", "password"]),
        DiscoveredEndpoint(path="/search", method="GET", parameters=["q"]),
        DiscoveredEndpoint(path="/api/user", method="GET", parameters=["id"]),
        DiscoveredEndpoint(path="/product", method="GET", parameters=["item"]),
        DiscoveredEndpoint(path="/comment", method="POST", parameters=["user", "text"]),
    ]

    bot.discover_endpoints(
        project_dir=args.project_dir,
        extra_endpoints=test_endpoints,
        probe_live=False,  # We already know the endpoints
    )

    print(f"\n{'=' * 70}")
    print(f"  SQL Injection AttackBot – Starting Scan")
    print(f"  Target: {args.target}")
    print(f"  Endpoints: {len(bot.endpoints)}")
    print(f"{'=' * 70}\n")

    report = bot.run_scan()

    # Save report if requested
    if args.output:
        bot.save_report(args.output)
        print(f"\nReport saved to: {args.output}")
    else:
        # Always save a default report
        default_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "scan_report.json",
        )
        bot.save_report(default_path)
        print(f"\nReport saved to: {default_path}")

    # Print scan log summary
    total = len(bot.scan_log)
    vulns = sum(1 for entry in bot.scan_log if entry.vulnerable)
    print(f"\nScan complete: {total} payloads tested, {vulns} vulnerabilities detected.")


if __name__ == "__main__":
    main()
