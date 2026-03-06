"""
static_scan_runner.py  –  Module 8
------------------------------------
Fallback scanner used when the sandbox fails to launch (or as a
supplementary analysis alongside the live scan).

Uses the existing StaticCodeAnalyzer from AttackBot/response_analyzer.py
and the bot's ``static_scan()`` method — **without modifying any AttackBot
code**.

Responsibilities
~~~~~~~~~~~~~~~~
1. Point the StaticCodeAnalyzer at the extracted project directory.
2. Collect findings (unsafe SQL patterns, string-concat queries, etc.).
3. Return results in a uniform dict format that report_service can merge.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

_BACKEND = os.path.dirname(os.path.abspath(__file__))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from AttackBot.SQL_Injections.response_analyzer import StaticCodeAnalyzer

logger = logging.getLogger(__name__)


# ── Supported extensions ──────────────────────────────────────────────────
_SCAN_EXTENSIONS = {".py", ".js", ".ts", ".php", ".html", ".jsx", ".tsx"}

# Directories to always skip (dependency trees, build artefacts, caches)
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "vendor", "bower_components",
    "coverage", ".cache", ".tox", "env", ".env", "out",
    "target", "bin", "obj", ".svn", ".hg",
}

# Max file size to scan (512 KB) — skip minified bundles
_MAX_FILE_SIZE = 512 * 1024


class StaticScanRunner:
    """
    Performs static-only code analysis on an extracted project directory.

    Parameters
    ----------
    project_dir : str
        Absolute path to the extracted upload.
    """

    def __init__(self, project_dir: str):
        self.project_dir = project_dir
        self._analyzer = StaticCodeAnalyzer()
        self._findings: List[Dict] = []

    # ── Public API ────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """
        Execute the static scan.

        Returns
        -------
        dict
            ``{success, findings, files_scanned, error}``
        """
        if not os.path.isdir(self.project_dir):
            return self._err(f"Project directory does not exist: {self.project_dir}")

        try:
            # Use our own walk that skips node_modules, dist, etc.
            # (StaticCodeAnalyzer.analyze_directory doesn't skip them)
            self._findings = self._safe_analyze()
            files_scanned = self._count_scannable_files()

            # Make file paths relative to project_dir for readability
            for f in self._findings:
                if "file" in f:
                    f["file"] = os.path.relpath(f["file"], self.project_dir)

            logger.info(
                "[StaticScanRunner] Found %d issues in %d files under %s",
                len(self._findings),
                files_scanned,
                self.project_dir,
            )

            return {
                "success": True,
                "findings": self._findings,
                "files_scanned": files_scanned,
                "error": None,
            }

        except Exception as exc:
            logger.exception("[StaticScanRunner] Static scan failed")
            return self._err(str(exc))

    @property
    def findings(self) -> List[Dict]:
        return list(self._findings)

    # ── Helpers ───────────────────────────────────────────────────────

    def _safe_analyze(self) -> List[Dict]:
        """Walk directory tree, skipping junk dirs and huge files."""
        all_findings: List[Dict] = []
        for dirpath, dirnames, filenames in os.walk(self.project_dir):
            # Prune directories we never want to enter
            dirnames[:] = [
                d for d in dirnames if d.lower() not in _SKIP_DIRS
            ]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in _SCAN_EXTENSIONS:
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                if size > _MAX_FILE_SIZE:
                    logger.debug("[StaticScanRunner] Skipping large file (%d KB): %s", size // 1024, fn)
                    continue
                all_findings.extend(self._analyzer.analyze_file(full))
        return all_findings

    def _count_scannable_files(self) -> int:
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.project_dir):
            dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in _SCAN_EXTENSIONS:
                    try:
                        if os.path.getsize(os.path.join(dirpath, fn)) <= _MAX_FILE_SIZE:
                            count += 1
                    except OSError:
                        pass
        return count

    @staticmethod
    def _err(msg: str) -> Dict[str, Any]:
        return {
            "success": False,
            "findings": [],
            "files_scanned": 0,
            "error": msg,
        }
