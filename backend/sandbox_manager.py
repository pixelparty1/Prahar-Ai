"""
sandbox_manager.py
------------------
Launches an uploaded website project inside a safe, temporary
sandbox environment on localhost.

Responsibilities:
  - Copy the project to a disposable temp folder (originals untouched)
  - Install dependencies (pip / npm / composer)
  - Start the server on a random free localhost port
  - Capture server logs
  - Return the running URL, port, and process ID

Supports:  Flask · Django · Node/Express · PHP
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, List

from framework_detector import FrameworkDetector


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class SandboxInstance:
    """A running sandbox server."""
    sandbox_id: str
    sandbox_dir: str
    original_dir: str
    framework: str
    host: str = "127.0.0.1"
    port: int = 0
    target_url: str = ""
    process: Optional[subprocess.Popen] = None
    pid: Optional[int] = None
    running: bool = False
    logs: List[str] = field(default_factory=list)


# ── Sandbox Manager ──────────────────────────────────────────────────────

class SandboxManager:
    """Launch and manage sandboxed website instances."""

    def __init__(self):
        self._instances: dict[str, SandboxInstance] = {}

    # ── Public: launch ────────────────────────────────────────────────

    def launch(
        self,
        project_dir: str,
        framework_info: Optional[dict] = None,
        port: Optional[int] = None,
        wait_timeout: float = 20.0,
    ) -> dict:
        """
        Launch the project in a sandbox.

        Parameters
        ----------
        project_dir : str
            Extracted project folder.
        framework_info : dict, optional
            Output of FrameworkDetector.detect().  Auto-detected if omitted.
        port : int, optional
            Force a specific port.  Random free port if omitted.
        wait_timeout : float
            Seconds to wait for the server to respond.

        Returns
        -------
        dict  {success, target_url, port, process_id, sandbox_id, error}
        """
        # 1 — Detect framework
        if framework_info is None:
            framework_info = FrameworkDetector().detect(project_dir)
        fw = framework_info["framework"]

        if fw == "unknown":
            return self._err("Cannot launch: framework not detected.")

        # Node projects need more time (npm install + server startup)
        if fw == "node" and wait_timeout <= 20.0:
            wait_timeout = 60.0

        # 2 — Copy project to temp sandbox folder
        sandbox_id = uuid.uuid4().hex[:12]
        sandbox_dir = os.path.join(
            tempfile.gettempdir(), "prahaar_sandbox", f"sandbox_{sandbox_id}"
        )
        try:
            shutil.copytree(
                project_dir,
                sandbox_dir,
                ignore=shutil.ignore_patterns(
                    "node_modules", ".git", "__pycache__", ".venv", "venv",
                ),
            )
        except Exception as exc:
            return self._err(f"Failed to copy project: {exc}")

        # 3 — Pick a free port
        if port is None:
            port = self._free_port()

        inst = SandboxInstance(
            sandbox_id=sandbox_id,
            sandbox_dir=sandbox_dir,
            original_dir=project_dir,
            framework=fw,
            port=port,
            target_url=f"http://127.0.0.1:{port}",
        )

        # 4 — Install dependencies (best-effort)
        dep_err = self._install_deps(inst, framework_info)
        if dep_err:
            inst.logs.append(f"[warn] dependency install: {dep_err}")

        # 5 — Start the server process
        start_err = self._start_server(inst, framework_info)
        if start_err:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
            return self._err(start_err)

        # 6 — Wait for the server to become ready
        if not self._wait_ready(inst, timeout=wait_timeout):
            self.stop(sandbox_id)
            return self._err(f"Server did not respond within {wait_timeout}s on port {port}.")

        inst.running = True
        self._instances[sandbox_id] = inst

        print(f"[SandboxManager] Running at {inst.target_url}  (PID {inst.pid})")
        return {
            "success": True,
            "target_url": inst.target_url,
            "port": inst.port,
            "process_id": inst.pid,
            "sandbox_id": sandbox_id,
            "error": None,
        }

    # ── Public: stop ──────────────────────────────────────────────────

    def stop(self, sandbox_id: str) -> bool:
        """Kill the server and delete the sandbox folder. Returns True if cleaned."""
        inst = self._instances.pop(sandbox_id, None)
        if inst is None:
            return False

        # Kill process
        if inst.process and inst.process.poll() is None:
            self._kill(inst.process.pid)
            try:
                inst.process.wait(timeout=5)
            except Exception:
                inst.process.kill()

        inst.running = False

        # Delete sandbox directory
        if os.path.exists(inst.sandbox_dir):
            shutil.rmtree(inst.sandbox_dir, ignore_errors=True)

        print(f"[SandboxManager] Stopped sandbox {sandbox_id}")
        return True

    def stop_all(self) -> int:
        count = 0
        for sid in list(self._instances):
            if self.stop(sid):
                count += 1
        return count

    def get_instance(self, sandbox_id: str) -> Optional[SandboxInstance]:
        return self._instances.get(sandbox_id)

    # ── Internal: install dependencies ────────────────────────────────

    def _install_deps(self, inst: SandboxInstance, fw_info: dict) -> Optional[str]:
        cwd = inst.sandbox_dir
        fw = fw_info["framework"]

        try:
            if fw in ("flask", "django"):
                req = os.path.join(cwd, "requirements.txt")
                if os.path.isfile(req):
                    r = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-r", req, "-q"],
                        cwd=cwd, capture_output=True, text=True, timeout=120,
                    )
                    if r.returncode != 0:
                        return r.stderr[:300]
                    inst.logs.append("pip install OK")

            elif fw == "node":
                if os.path.isfile(os.path.join(cwd, "package.json")):
                    r = subprocess.run(
                        ["npm", "install", "--silent"],
                        cwd=cwd, capture_output=True, text=True,
                        timeout=120, shell=True,
                    )
                    if r.returncode != 0:
                        return r.stderr[:300]
                    inst.logs.append("npm install OK")

        except subprocess.TimeoutExpired:
            return "Dependency install timed out."
        except FileNotFoundError as exc:
            return f"Tool not found: {exc}"

        return None

    # ── Internal: start server ────────────────────────────────────────

    def _start_server(self, inst: SandboxInstance, fw_info: dict) -> Optional[str]:
        """Launch the server process. Returns an error string or None."""
        fw = fw_info["framework"]
        port = inst.port
        cwd = inst.sandbox_dir
        entry = fw_info.get("entry_point")

        cmd = self._build_cmd(fw, entry, port, cwd)
        if cmd is None:
            return f"No launch command for framework '{fw}'"

        try:
            log_path = os.path.join(
                tempfile.gettempdir(), "prahaar_sandbox", f"log_{inst.sandbox_id}.txt"
            )
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            log_fh = open(log_path, "w", encoding="utf-8")

            env = os.environ.copy()
            env["PORT"] = str(port)
            env["FLASK_APP"] = entry or "app.py"
            env["NODE_ENV"] = "development"
            # Do NOT set WERKZEUG_RUN_MAIN — it causes Werkzeug to expect
            # WERKZEUG_SERVER_FD which we don't provide.

            # npm on Windows requires shell=True
            use_shell = (os.name == "nt" and cmd and cmd[0] == "npm")

            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                env=env,
                shell=use_shell,
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
            inst.process = proc
            inst.pid = proc.pid
            inst.logs.append(f"Started PID {proc.pid}: {' '.join(cmd)}")
        except Exception as exc:
            return f"Could not start server: {exc}"

        return None

    @staticmethod
    def _build_cmd(fw, entry, port, cwd) -> list[str] | None:
        if fw == "flask":
            ep = entry or "app.py"
            if os.path.isfile(os.path.join(cwd, ep)):
                return [sys.executable, ep]
            return [
                sys.executable, "-m", "flask", "run",
                "--host", "127.0.0.1", "--port", str(port),
            ]
        if fw == "django":
            return [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"]
        if fw == "node":
            # Try to read the start script from package.json
            pkg_json = os.path.join(cwd, "package.json")
            if os.path.isfile(pkg_json):
                try:
                    import json
                    with open(pkg_json, "r", encoding="utf-8") as fh:
                        pkg = json.load(fh)
                    # Use "scripts.start" if available (e.g. "node server.js")
                    start_script = pkg.get("scripts", {}).get("start", "")
                    if start_script:
                        # npm start will use the PORT env var
                        return ["npm", "start"]
                    # Fallback to "main" field
                    main_file = pkg.get("main")
                    if main_file and os.path.isfile(os.path.join(cwd, main_file)):
                        return ["node", main_file]
                except Exception:
                    pass
            ep = entry or "server.js"
            if os.path.isfile(os.path.join(cwd, ep)):
                return ["node", ep]
            # Last resort: try common entry points
            for candidate in ("app.js", "index.js", "main.js", "server.js"):
                if os.path.isfile(os.path.join(cwd, candidate)):
                    return ["node", candidate]
            return ["npm", "start"]
        if fw == "php":
            return ["php", "-S", f"127.0.0.1:{port}"]
        return None

    # ── Internal: wait for readiness ──────────────────────────────────

    @staticmethod
    def _wait_ready(inst: SandboxInstance, timeout: float) -> bool:
        import requests
        start = time.time()
        while time.time() - start < timeout:
            if inst.process and inst.process.poll() is not None:
                return False
            try:
                r = requests.get(inst.target_url, timeout=2)
                if r.status_code < 500:
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    # ── Internal: helpers ─────────────────────────────────────────────

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    @staticmethod
    def _kill(pid: int):
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        else:
            import signal
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass

    @staticmethod
    def _err(msg: str) -> dict:
        return {"success": False, "target_url": None, "port": None,
                "process_id": None, "sandbox_id": None, "error": msg}
