"""
framework_detector.py
---------------------
Detects the web framework of an uploaded project by scanning
for known file-name and content indicators.

Supported frameworks:
  - Flask       (Python)
  - Django      (Python)
  - Node/Express (JavaScript)
  - PHP

Returns one of: "flask", "django", "node", "php", "unknown"
"""

import os
import re


class FrameworkDetector:
    """Scan a project directory and identify its web framework."""

    def detect(self, project_dir: str) -> dict:
        """
        Analyse files in *project_dir* and return framework info.

        Returns
        -------
        dict
            {
                "framework":     str,   # "flask" | "django" | "node" | "php" | "unknown"
                "entry_point":   str,   # e.g. "app.py", "manage.py", "server.js", "index.php"
                "start_command": str,   # command to launch the server
                "indicators":    list,  # evidence that led to the decision
            }
        """
        if not os.path.isdir(project_dir):
            return self._result("unknown", indicators=["Directory not found"])

        files = self._list_files(project_dir)
        basenames = {os.path.basename(f) for f in files}

        # Priority order: Django → Flask → Node/Express → PHP → unknown
        result = (
            self._check_django(project_dir, files, basenames)
            or self._check_flask(project_dir, files, basenames)
            or self._check_node(project_dir, files, basenames)
            or self._check_php(project_dir, files, basenames)
        )
        return result or self._result("unknown", indicators=["No framework indicators found"])

    # ── Flask ─────────────────────────────────────────────────────────

    def _check_flask(self, root, files, basenames) -> dict | None:
        indicators = []
        entry_point = None

        for f in files:
            if not f.endswith(".py"):
                continue
            try:
                text = self._read(os.path.join(root, f))
            except OSError:
                continue

            if re.search(r"from\s+flask\s+import|import\s+flask", text, re.I):
                indicators.append(f"Flask import in {f}")
            if re.search(r"Flask\s*\(", text):
                indicators.append(f"Flask() instantiation in {f}")
                if entry_point is None:
                    entry_point = f

        if not indicators:
            return None

        entry_point = entry_point or self._pick(basenames, ["app.py", "main.py", "run.py", "server.py"])
        return self._result(
            "flask",
            entry_point=entry_point or "app.py",
            start_command=f"python {entry_point or 'app.py'}",
            indicators=indicators,
        )

    # ── Django ────────────────────────────────────────────────────────

    def _check_django(self, root, files, basenames) -> dict | None:
        indicators = []
        if "manage.py" in basenames:
            indicators.append("manage.py found")

        for f in files:
            if f.endswith("settings.py"):
                try:
                    text = self._read(os.path.join(root, f))
                    if "INSTALLED_APPS" in text:
                        indicators.append(f"Django settings in {f}")
                except OSError:
                    pass

        if not indicators:
            return None

        return self._result(
            "django",
            entry_point="manage.py",
            start_command="python manage.py runserver 127.0.0.1:{port}",
            indicators=indicators,
        )

    # ── Node / Express ────────────────────────────────────────────────

    def _check_node(self, root, files, basenames) -> dict | None:
        indicators = []
        if "package.json" not in basenames:
            return None

        indicators.append("package.json found")

        # Check for Express dependency
        try:
            import json
            text = self._read(os.path.join(root, "package.json"))
            pkg = json.loads(text)
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            if "express" in deps:
                indicators.append("express in dependencies")
        except Exception:
            pass

        entry_point = self._pick(basenames, ["server.js", "app.js", "index.js", "main.js"])
        return self._result(
            "node",
            entry_point=entry_point or "server.js",
            start_command=f"node {entry_point or 'server.js'}",
            indicators=indicators,
        )

    # ── PHP ───────────────────────────────────────────────────────────

    def _check_php(self, root, files, basenames) -> dict | None:
        php_files = [f for f in files if f.endswith(".php")]
        if not php_files:
            return None

        entry = "index.php" if "index.php" in basenames else php_files[0]
        return self._result(
            "php",
            entry_point=entry,
            start_command="php -S 127.0.0.1:{port}",
            indicators=[f"{len(php_files)} PHP file(s) found"],
        )

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _result(framework, entry_point=None, start_command=None, indicators=None) -> dict:
        return {
            "framework": framework,
            "entry_point": entry_point,
            "start_command": start_command,
            "indicators": indicators or [],
        }

    @staticmethod
    def _pick(basenames, candidates) -> str | None:
        for c in candidates:
            if c in basenames:
                return c
        return None

    @staticmethod
    def _list_files(directory, max_depth=4) -> list[str]:
        result = []
        base = os.path.abspath(directory)
        skip = {"node_modules", ".git", "__pycache__", ".venv", "venv"}
        for dirpath, dirnames, filenames in os.walk(directory):
            depth = os.path.relpath(dirpath, base).count(os.sep)
            if depth >= max_depth:
                dirnames.clear()
                continue
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                result.append(os.path.relpath(os.path.join(dirpath, fn), base).replace("\\", "/"))
        return result

    @staticmethod
    def _read(path, limit=64_000) -> str:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
