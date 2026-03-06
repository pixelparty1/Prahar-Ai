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

Supports:  Flask · Django · Node/Express · Next.js · Vite · PHP

Node Sandbox (fully redesigned — 10-step intelligent launcher):
  Step 1  — Detect Node project type (Express, Next.js, Vite, React, NestJS, …)
  Step 2  — Install dependencies via npm install (fatal on failure)
  Step 3  — Detect start command from package.json scripts
  Step 4  — Detect common entry files if no script exists
  Step 5  — Framework-specific startup (next, vite, express, nestjs)
  Step 6  — Frontend-only detection → run build, scan static output
  Step 7  — Smart health-check (probe every 1 s up to 60 s)
  Step 8  — Capture last 20 log lines on failure
  Step 9  — Clear sandbox failure reason in report output
  Step 10 — Safe static-scan fallback (no crash on failure)
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from framework_detector import FrameworkDetector


# ── Node project type constants ───────────────────────────────────────────

class NodeProjectType:
    EXPRESS   = "express"
    NEXTJS    = "nextjs"
    VITE      = "vite"
    REACT     = "react"
    NESTJS    = "nestjs"
    FULLSTACK = "fullstack"
    STATIC    = "static"
    GENERIC   = "generic"


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
    # Node-specific metadata
    node_project_type: str = "unknown"   # express | nextjs | vite | react | nestjs | static | generic
    is_frontend_only: bool = False
    static_build_dir: Optional[str] = None  # populated for frontend-only projects


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
                    "dist", "build", ".next", ".nuxt",
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

        # 4 — Install dependencies
        dep_err = self._install_deps(inst, framework_info)
        if dep_err:
            inst.logs.append(f"[warn] dependency install: {dep_err}")
            # For Node, dependency failure is fatal — fall back to static scan
            if fw == "node":
                shutil.rmtree(sandbox_dir, ignore_errors=True)
                return self._err(
                    f"Node dependency install failed: {dep_err}",
                    logs=inst.logs,
                    node_project_type=inst.node_project_type,
                )

        # 5 — Start the server process
        if fw == "node":
            start_err = self._start_node_server_full(inst, framework_info)
            if start_err:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
                return self._err(
                    start_err,
                    logs=inst.logs,
                    node_project_type=inst.node_project_type,
                    is_frontend_only=inst.is_frontend_only,
                    static_build_dir=inst.static_build_dir,
                )
            if not inst.running and not inst.is_frontend_only:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
                return self._err(
                    "Node server failed to start after all strategies. "
                    "The project may require environment variables or a database.",
                    logs=inst.logs,
                    node_project_type=inst.node_project_type,
                    is_frontend_only=inst.is_frontend_only,
                    static_build_dir=inst.static_build_dir,
                )
        else:
            start_err = self._start_server(inst, framework_info)
            if start_err:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
                return self._err(start_err, logs=inst.logs)
            if not self._wait_ready(inst, timeout=wait_timeout):
                extra_logs = self._read_all_logs(inst)
                inst.logs.extend(extra_logs)
                self.stop(sandbox_id)
                return self._err(
                    f"Server did not respond within {wait_timeout}s on port {port}.",
                    logs=inst.logs,
                )

        self._instances[sandbox_id] = inst
        print(f"[SandboxManager] Running at {inst.target_url}  (PID {inst.pid})")
        return {
            "success": True,
            "target_url": inst.target_url,
            "port": inst.port,
            "process_id": inst.pid,
            "sandbox_id": sandbox_id,
            "error": None,
            "logs": inst.logs,
            "node_project_type": inst.node_project_type,
            "is_frontend_only": inst.is_frontend_only,
            "static_build_dir": inst.static_build_dir,
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

    # ══════════════════════════════════════════════════════════════════
    # STEP 2 — INSTALL DEPENDENCIES
    # ══════════════════════════════════════════════════════════════════

    def _install_deps(self, inst: SandboxInstance, fw_info: dict) -> Optional[str]:
        """Install project dependencies. Returns an error string or None."""
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
                    inst.logs.append("[pip] install OK")

            elif fw == "node":
                # Always run npm install — required before any start strategy
                pkg_json = os.path.join(cwd, "package.json")
                if not os.path.isfile(pkg_json):
                    inst.logs.append("[node] No package.json — skipping npm install")
                    return None

                inst.logs.append("[node] Running npm install...")
                r = subprocess.run(
                    ["npm", "install", "--prefer-offline", "--no-audit", "--no-fund"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    shell=(os.name == "nt"),
                )
                stderr_tail = (r.stderr or "")[-500:]
                stdout_tail = (r.stdout or "")[-300:]
                if r.returncode != 0:
                    inst.logs.append(f"[node] npm install FAILED (exit {r.returncode})")
                    if stderr_tail:
                        inst.logs.append(f"[node] npm install stderr: {stderr_tail}")
                    return f"npm install failed (exit {r.returncode}): {stderr_tail[:200]}"
                inst.logs.append("[node] npm install OK")
                if stdout_tail:
                    inst.logs.append(f"[node] npm output: {stdout_tail[-200:]}")

        except subprocess.TimeoutExpired:
            return "Dependency install timed out (180 s)."
        except FileNotFoundError as exc:
            return f"Tool not found (is npm installed?): {exc}"

        return None

    # ── Non-Node server start ────────────────────────────────────────

    def _start_server(self, inst: SandboxInstance, fw_info: dict) -> Optional[str]:
        """Launch the server process for Flask / Django / PHP."""
        fw    = fw_info["framework"]
        port  = inst.port
        cwd   = inst.sandbox_dir
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
            env["PORT"]     = str(port)
            env["FLASK_APP"] = entry or "app.py"
            env["NODE_ENV"] = "development"
            # Do NOT set WERKZEUG_RUN_MAIN — it causes Werkzeug to expect
            # WERKZEUG_SERVER_FD which we don't provide.

            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                env=env,
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
            inst.process = proc
            inst.pid      = proc.pid
            inst.logs.append(f"Started PID {proc.pid}: {' '.join(str(c) for c in cmd)}")
        except Exception as exc:
            return f"Could not start server: {exc}"

        return None

    # ══════════════════════════════════════════════════════════════════
    # STEP 1 — DETECT NODE PROJECT TYPE
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _detect_node_project(cwd: str) -> Dict[str, Any]:
        """
        Read package.json and inspect the filesystem to classify the Node project.

        Returns a dict with keys:
          type            : NodeProjectType constant
          scripts         : dict of npm scripts
          deps            : set of all dependency names
          main_field      : package.json "main" value (or None)
          is_frontend_only: True when no server component detected
          build_out_dirs  : candidate output directories for static builds
        """
        result: Dict[str, Any] = {
            "type": NodeProjectType.GENERIC,
            "scripts": {},
            "deps": set(),
            "main_field": None,
            "is_frontend_only": False,
            "build_out_dirs": ["dist", "build", "out", ".next", "public"],
        }

        pkg_path = os.path.join(cwd, "package.json")
        if not os.path.isfile(pkg_path):
            return result

        try:
            with open(pkg_path, "r", encoding="utf-8", errors="replace") as fh:
                pkg = json.load(fh)
        except Exception:
            return result

        scripts   = pkg.get("scripts") or {}
        raw_deps: dict = {}
        raw_deps.update(pkg.get("dependencies") or {})
        raw_deps.update(pkg.get("devDependencies") or {})
        dep_names: set = set(raw_deps.keys())

        result["scripts"]    = scripts
        result["deps"]       = dep_names
        result["main_field"] = pkg.get("main")

        # ── Classify project type ──────────────────────────────────────
        has_next    = "next" in dep_names
        has_vite    = "vite" in dep_names
        has_express = "express" in dep_names
        has_fastify = "fastify" in dep_names
        has_koa     = "koa" in dep_names
        has_hapi    = "@hapi/hapi" in dep_names or "hapi" in dep_names
        has_nest    = any(d in dep_names for d in ("@nestjs/core", "@nestjs/common"))
        has_react   = "react" in dep_names or "react-dom" in dep_names
        has_vue     = "vue" in dep_names
        has_angular = "@angular/core" in dep_names
        has_server_dep = has_express or has_fastify or has_koa or has_hapi or has_nest

        # Known server entry files present on disk?
        server_candidates = [
            "server.js", "server.ts", "app.js", "app.ts",
            "index.js",  "index.ts",  "main.js", "main.ts",
            os.path.join("src", "server.js"), os.path.join("src", "server.ts"),
            os.path.join("src", "app.js"),    os.path.join("src", "app.ts"),
            os.path.join("src", "index.js"),  os.path.join("src", "index.ts"),
            os.path.join("src", "main.js"),   os.path.join("src", "main.ts"),
        ]
        has_server_file = any(
            os.path.isfile(os.path.join(cwd, f)) for f in server_candidates
        )

        if has_nest:
            proj_type = NodeProjectType.NESTJS
        elif has_next:
            proj_type = NodeProjectType.NEXTJS
        elif has_vite and not has_server_dep:
            proj_type = NodeProjectType.VITE
        elif has_express or has_fastify or has_koa or has_hapi:
            proj_type = NodeProjectType.EXPRESS
        elif (has_react or has_vue or has_angular) and not has_server_dep and not has_server_file:
            proj_type = NodeProjectType.REACT
        elif has_server_dep or has_server_file:
            proj_type = NodeProjectType.GENERIC
        else:
            proj_type = NodeProjectType.STATIC

        # Frontend-only: UI framework, no server dep, no server entry file
        is_frontend_only = (
            proj_type in (NodeProjectType.VITE, NodeProjectType.REACT, NodeProjectType.STATIC)
            and not has_server_dep
            and not has_server_file
        )

        result["type"]             = proj_type
        result["is_frontend_only"] = is_frontend_only
        return result

    # ══════════════════════════════════════════════════════════════════
    # STEPS 3–7 — FULL NODE SERVER LAUNCHER
    # ══════════════════════════════════════════════════════════════════

    def _start_node_server_full(
        self, inst: SandboxInstance, fw_info: dict
    ) -> Optional[str]:
        """
        Intelligent Node server launcher implementing Steps 1–8.

        • Detects project type (Step 1)
        • Handles frontend-only via build path (Step 6)
        • Builds prioritised strategy list (Steps 3–5)
        • Probes every 1 s up to 60 s per strategy (Step 7)
        • Captures last 20 log lines on failure (Step 8)

        Always returns None; caller checks inst.running / inst.is_frontend_only.
        """
        cwd = inst.sandbox_dir
        proj_info = self._detect_node_project(cwd)
        inst.node_project_type = proj_info["type"]
        inst.is_frontend_only  = proj_info["is_frontend_only"]

        inst.logs.append(
            f"[node] Project type: {inst.node_project_type}  "
            f"(frontend_only={inst.is_frontend_only})"
        )

        # ── STEP 6: Frontend-only — build & expose static dir ─────────
        if inst.is_frontend_only:
            self._handle_frontend_only(inst, proj_info, cwd)
            return None  # no live server; static scanner will take over

        # ── STEPS 3–5: Build ordered strategy list ────────────────────
        strategies = self._build_node_strategies(proj_info, cwd)
        if not strategies:
            strategies = [("npm start (fallback)", ["npm", "start"])]

        env = os.environ.copy()
        env["PORT"]        = str(inst.port)
        env["NODE_ENV"]    = "development"
        env["SERVER_PORT"] = str(inst.port)
        env["HTTP_PORT"]   = str(inst.port)
        env["APP_PORT"]    = str(inst.port)

        inst.logs.append(
            f"[node] Trying {len(strategies)} startup strategies on port {inst.port}"
        )

        # ── STEP 7: Probe with exponential backoff, up to 30 seconds per strategy
        per_strategy_timeout = 30.0

        for idx, (description, cmd) in enumerate(strategies, 1):
            inst.logs.append(f"[node] Strategy {idx}/{len(strategies)}: {description}")

            # Kill previous attempt cleanly
            if inst.process and inst.process.poll() is None:
                self._kill(inst.process.pid)
                try:
                    inst.process.wait(timeout=5)
                except Exception:
                    pass
                inst.process = None
                inst.pid = None

            log_path = os.path.join(
                tempfile.gettempdir(), "prahaar_sandbox",
                f"log_{inst.sandbox_id}_s{idx}.txt",
            )
            os.makedirs(os.path.dirname(log_path), exist_ok=True)

            try:
                log_fh    = open(log_path, "w", encoding="utf-8")
                use_shell = os.name == "nt" and bool(cmd) and cmd[0] in ("npm", "npx")
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
                inst.pid     = proc.pid
                inst.logs.append(f"[node] Launched PID {proc.pid} — {description}")
            except Exception as exc:
                inst.logs.append(f"[node] Strategy {idx} launch error: {exc}")
                continue

            # ── STEP 7: Smart health-check ─────────────────────────────
            if self._wait_ready(inst, timeout=per_strategy_timeout, interval=0.5):
                inst.running = True
                inst.logs.append(f"[node] Strategy {idx} SUCCESS: {description}")
                print(
                    f"[SandboxManager] Node server ready — {description}  (PID {inst.pid})"
                )
                return None

            # ── STEP 8: Capture last 20 lines ─────────────────────────
            tail = self._read_strategy_log(log_path, lines=20)
            if tail:
                inst.logs.append(f"[node] Strategy {idx} log tail:")
                inst.logs.extend(f"  {ln}" for ln in tail)
            inst.logs.append(
                f"[node] Strategy {idx} failed after {per_strategy_timeout}s: {description}"
            )

        inst.logs.append("[node] All startup strategies exhausted.")
        return None  # caller checks inst.running

    # ── STEP 6: Handle frontend-only projects ─────────────────────────

    def _handle_frontend_only(
        self, inst: SandboxInstance, proj_info: Dict[str, Any], cwd: str
    ) -> None:
        """
        For frontend-only projects (React / Vite / static):
        run npm run build, then point inst.static_build_dir at the output.
        The static scanner will use that directory.
        """
        scripts = proj_info.get("scripts") or {}
        inst.logs.append("[node] Frontend-only — running build step")

        build_cmd: Optional[list] = None
        if "build" in scripts:
            build_cmd = ["npm", "run", "build"]
        elif "export" in scripts:
            build_cmd = ["npm", "run", "export"]

        if build_cmd:
            inst.logs.append(f"[node] Build command: {' '.join(build_cmd)}")
            try:
                r = subprocess.run(
                    build_cmd,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    shell=(os.name == "nt"),
                )
                if r.returncode == 0:
                    inst.logs.append("[node] Build succeeded")
                else:
                    inst.logs.append(
                        f"[node] Build failed (exit {r.returncode}): "
                        f"{(r.stderr or '')[-300:]}"
                    )
            except subprocess.TimeoutExpired:
                inst.logs.append("[node] Build timed out")
            except Exception as exc:
                inst.logs.append(f"[node] Build error: {exc}")

        # Locate build output directory
        for out_dir in proj_info.get("build_out_dirs", ["dist", "build", "out"]):
            full_out = os.path.join(cwd, out_dir)
            if os.path.isdir(full_out):
                inst.static_build_dir = full_out
                inst.logs.append(f"[node] Static output dir: {full_out}")
                break

        if not inst.static_build_dir:
            inst.static_build_dir = cwd
            inst.logs.append("[node] Using project root as static source")

    # ══════════════════════════════════════════════════════════════════
    # STEPS 3–5 — BUILD ORDERED STRATEGY LIST
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _build_node_strategies(
        proj_info: Dict[str, Any], cwd: str
    ) -> List[tuple]:
        """
        Return an ordered list of (description, cmd) launch strategies.

        Priority follows the spec:
          STEP 3 — scripts: start > dev > serve > preview
          STEP 4 — common entry files: server.js / app.js / index.js / main.js
          STEP 5 — framework-specific (next, vite, express, nestjs)
        """
        strategies: List[tuple] = []
        scripts  = proj_info.get("scripts") or {}
        deps     = proj_info.get("deps") or set()
        ptype    = proj_info.get("type", NodeProjectType.GENERIC)
        main_f   = proj_info.get("main_field")

        # ── STEP 5: Framework-specific startup ────────────────────────

        if ptype == NodeProjectType.NESTJS:
            for s in ("start:dev", "start", "start:prod", "start:debug"):
                if s in scripts:
                    strategies.append((f"npm run {s} (NestJS)", ["npm", "run", s]))

        elif ptype == NodeProjectType.NEXTJS:
            if "dev" in scripts:
                strategies.append(("npm run dev (Next.js)", ["npm", "run", "dev"]))
            strategies.append(("npx next dev (Next.js)", ["npx", "next", "dev"]))
            if "start" in scripts:
                strategies.append(("npm run start (Next.js)", ["npm", "run", "start"]))

        elif ptype == NodeProjectType.VITE:
            for s in ("dev", "preview", "serve", "start"):
                if s in scripts:
                    strategies.append((f"npm run {s} (Vite)", ["npm", "run", s]))
            strategies.append(("npx vite (Vite)", ["npx", "vite"]))

        elif ptype == NodeProjectType.EXPRESS:
            # STEP 3: scripts first
            for s in ("start", "dev", "serve"):
                if s in scripts:
                    strategies.append(
                        (f"npm run {s} (Express)", ["npm", "run", s])
                    )
            # STEP 4: common entry files
            for candidate in ("server.js", "app.js", "index.js", "main.js"):
                if os.path.isfile(os.path.join(cwd, candidate)):
                    strategies.append(
                        (f"node {candidate} (Express entry)", ["node", candidate])
                    )

        else:
            # STEP 3: generic script priority
            for s in ("start", "dev", "serve", "preview"):
                if s in scripts:
                    strategies.append((f"npm run {s}", ["npm", "run", s]))

        # ── STEP 3: npm run start as broad fallback ───────────────────
        if "start" in scripts:
            cmd = ["npm", "run", "start"]
            if not any(c == cmd for _, c in strategies):
                strategies.append(("npm run start", cmd))

        # ── STEP 4: package.json "main" field ─────────────────────────
        if main_f and os.path.isfile(os.path.join(cwd, main_f)):
            cmd = ["node", main_f]
            if not any(c == cmd for _, c in strategies):
                strategies.append((f"node {main_f} (main)", cmd))

        # ── STEP 4: common entry file scan ────────────────────────────
        entry_candidates = [
            "server.js",                       "server.ts",
            "app.js",                          "app.ts",
            "index.js",                        "index.ts",
            "main.js",                         "main.ts",
            os.path.join("src", "server.js"),  os.path.join("src", "server.ts"),
            os.path.join("src", "app.js"),     os.path.join("src", "app.ts"),
            os.path.join("src", "index.js"),   os.path.join("src", "index.ts"),
            os.path.join("src", "main.js"),    os.path.join("src", "main.ts"),
        ]
        for candidate in entry_candidates:
            full = os.path.join(cwd, candidate)
            if not os.path.isfile(full):
                continue
            if candidate.endswith(".ts"):
                tsnode = os.path.join(
                    cwd, "node_modules", ".bin",
                    "ts-node" + (".cmd" if os.name == "nt" else ""),
                )
                if not os.path.isfile(tsnode):
                    continue
                cmd  = [tsnode, candidate]
                disp = f"ts-node {candidate}"
            else:
                cmd  = ["node", candidate]
                disp = f"node {candidate}"
            if not any(c == cmd for _, c in strategies):
                strategies.append((disp, cmd))

        # ── Last resort ───────────────────────────────────────────────
        if not strategies:
            strategies.append(("npm start (last resort)", ["npm", "start"]))

        return strategies

    # ══════════════════════════════════════════════════════════════════
    # STEP 7 — SMART SERVER HEALTH CHECK
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _wait_ready(
        inst: SandboxInstance,
        timeout: float,
        interval: float = 0.5,
    ) -> bool:
        """
        Probe inst.target_url with exponential backoff up to `timeout` seconds.
        Starts fast (0.2 s) and backs off to `interval` cap.
        A response with status_code < 500 is considered success.
        Uses a persistent session to avoid TCP handshake overhead per probe.
        Detects early process exit to avoid wasting time.
        """
        import requests as _req
        sess = _req.Session()
        start = time.time()
        current_interval = 0.2  # start fast
        max_interval = interval
        try:
            while time.time() - start < timeout:
                if inst.process and inst.process.poll() is not None:
                    return False  # process exited early — no point waiting
                try:
                    r = sess.get(inst.target_url, timeout=2, allow_redirects=True)
                    if r.status_code < 500:
                        return True
                except _req.ConnectionError:
                    pass  # server not ready yet — expected
                except Exception:
                    pass
                time.sleep(current_interval)
                current_interval = min(current_interval * 1.5, max_interval)
        finally:
            sess.close()
        return False

    # ══════════════════════════════════════════════════════════════════
    # STEP 8 — CAPTURE SERVER LOGS (last 20 lines)
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _read_strategy_log(log_path: str, lines: int = 20) -> List[str]:
        """Read the last N lines from a strategy log file."""
        if not os.path.isfile(log_path):
            return []
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                all_lines = fh.readlines()
            tail = all_lines[-lines:]
            return [ln.rstrip() for ln in tail if ln.strip()]
        except OSError:
            return []

    def _read_all_logs(self, inst: SandboxInstance) -> List[str]:
        """Collect log tails (20 lines each) from all strategy log files."""
        base      = os.path.join(tempfile.gettempdir(), "prahaar_sandbox")
        collected: List[str] = []

        main_log = os.path.join(base, f"log_{inst.sandbox_id}.txt")
        tail = self._read_strategy_log(main_log, 20)
        if tail:
            collected.append("[main log tail]")
            collected.extend(tail)

        for i in range(1, 15):
            p = os.path.join(base, f"log_{inst.sandbox_id}_s{i}.txt")
            if not os.path.isfile(p):
                break
            tail = self._read_strategy_log(p, 20)
            if tail:
                collected.append(f"[strategy {i} log tail]")
                collected.extend(tail)

        return collected

    @staticmethod
    def _build_cmd(fw, entry, port, cwd):
        """Build launch command for non-Node frameworks."""
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
        if fw == "php":
            return ["php", "-S", f"127.0.0.1:{port}"]
        return None

    # ── Internal: helpers ─────────────────────────────────────────────

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    @staticmethod
    def _kill(pid: int):
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
            )
        else:
            import signal
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass

    # ══════════════════════════════════════════════════════════════════
    # STEPS 9–10 — STRUCTURED ERROR RESPONSE & STATIC FALLBACK SIGNAL
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _err(
        msg: str,
        logs: list = None,
        node_project_type: str = "unknown",
        is_frontend_only: bool = False,
        static_build_dir: Optional[str] = None,
    ) -> dict:
        """
        Structured failure response.

        STEP 9  — includes a clear, human-readable failure reason (msg).
        STEP 10 — is_frontend_only / static_build_dir signal the caller to
                  run StaticSourceAnalyzer instead of crashing the pipeline.
        """
        return {
            "success": False,
            "target_url": None,
            "port": None,
            "process_id": None,
            "sandbox_id": None,
            "error": msg,
            "logs": logs or [],
            "node_project_type": node_project_type,
            "is_frontend_only": is_frontend_only,
            "static_build_dir": static_build_dir,
        }
