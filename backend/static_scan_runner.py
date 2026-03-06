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
import re
import sys
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
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

# Directories that are guaranteed to contain frontend-only code
_FRONTEND_DIRS = {
    "components", "pages", "views", "ui", "hooks", "context", "store",
    "reducers", "actions", "containers", "atoms", "molecules", "organisms",
    "layouts", "screens", "features", "assets", "styles", "public", "static",
    "__tests__", "test", "tests", "spec", "mocks",
}

# Directories that indicate backend/server-side code
_BACKEND_DIRS = {
    "server", "api", "routes", "controllers", "middleware", "models",
    "services", "db", "database", "repo", "repository", "lib",
}

# File name patterns that identify frontend React/UI component files
_FRONTEND_FILENAME_RE = re.compile(
    r"(Component|Page|View|Screen|Layout|Widget|Dialog|Modal|Button|Form|Card|"
    r"Header|Footer|Navbar|Sidebar|Panel|Container|Provider|Context|Reducer|Action"
    r"|\.stories\.|\.test\.|\.spec\.)",
    re.IGNORECASE,
)


# Top-level function so ProcessPoolExecutor can pickle it
def _analyze_one_file(filepath: str) -> List[Dict]:
    analyzer = StaticCodeAnalyzer()
    return analyzer.analyze_file(filepath)


class StaticScanRunner:
    """
    Performs static-only code analysis on an extracted project directory.

    Parameters
    ----------
    project_dir : str
        Absolute path to the extracted upload.
    """

    # Resource-aware concurrency: cap workers so we don't overwhelm the system
    _MAX_WORKERS = min(32, (os.cpu_count() or 2) * 4)

    def __init__(self, project_dir: str):
        self.project_dir = project_dir
        self._analyzer = StaticCodeAnalyzer()
        self._findings: List[Dict] = []
        self._scannable_files: Optional[List[str]] = None

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
            # Collect scannable file list once and reuse it
            self._scannable_files = self._collect_scannable_files()
            files_scanned = len(self._scannable_files)

            # Use our own walk that skips node_modules, dist, etc.
            # (StaticCodeAnalyzer.analyze_directory doesn't skip them)
            self._findings = self._safe_analyze()

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
        """Analyze files in parallel using ProcessPoolExecutor (CPU-bound)."""
        files = self._scannable_files or self._collect_scannable_files()
        if not files:
            return []

        all_findings: List[Dict] = []

        # ProcessPoolExecutor for true CPU parallelism; fallback to threads
        try:
            Executor = ProcessPoolExecutor
            pool = Executor(max_workers=self._MAX_WORKERS)
        except Exception:
            Executor = ThreadPoolExecutor
            pool = Executor(max_workers=self._MAX_WORKERS)

        with pool:
            future_to_file = {pool.submit(_analyze_one_file, f): f for f in files}
            for future in as_completed(future_to_file):
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    logger.debug("[StaticScanRunner] Error scanning %s: %s",
                                 future_to_file[future], exc)
        return all_findings

    @staticmethod
    def _is_backend_file(filepath: str, ext: str) -> bool:
        """
        Return True if this file is likely backend/server-side code that
        could contain SQL injection vulnerabilities.

        Rules:
        - .py and .php are always backend.
        - .tsx and .jsx are always React frontend — never backend SQL.
        - .ts and .js are backend only if located in a backend directory
          OR not in a known frontend directory.
        - .html is skipped (templates may contain JS but not SQL logic).
        """
        if ext in (".py", ".php"):
            return True
        if ext in (".tsx", ".jsx", ".html", ".htm"):
            return False
        if ext in (".js", ".ts"):
            # Normalise path separators and split into parts
            parts = set(p.lower() for p in filepath.replace("\\", "/").split("/"))
            # Explicit backend directory in path → scan it
            if parts & _BACKEND_DIRS:
                return True
            # Explicit frontend directory → skip
            if parts & _FRONTEND_DIRS:
                return False
            # Frontend filename pattern → skip
            filename = os.path.basename(filepath)
            if _FRONTEND_FILENAME_RE.search(filename):
                return False
            # Default: scan generic .js/.ts files (e.g. root-level server.js)
            return True
        return False

    def _collect_scannable_files(self) -> List[str]:
        """Walk once and return list of backend files eligible for scanning."""
        result: List[str] = []
        for dirpath, dirnames, filenames in os.walk(self.project_dir):
            dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in _SCAN_EXTENSIONS:
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(full) > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                if not self._is_backend_file(full, ext):
                    continue
                result.append(full)
        return result

    @staticmethod
    def _err(msg: str) -> Dict[str, Any]:
        return {
            "success": False,
            "findings": [],
            "files_scanned": 0,
            "error": msg,
        }
