"""
cleanup_manager.py
------------------
Ensures no uploaded project data persists after a scan is complete.

Responsibilities:
  - Kill a running sandbox server process
  - Delete the temporary sandbox directory
  - Delete the extracted upload directory
  - Provide a one-call full cleanup
"""

import os
import shutil
import subprocess


class CleanupManager:
    """Clean up sandbox processes and temporary project files."""

    @staticmethod
    def kill_process(pid: int) -> bool:
        """
        Kill a process by PID (including child processes on Windows).

        Returns True if the kill command was issued successfully.
        """
        if pid is None:
            return False
        try:
            if os.name == "nt":
                # Windows: taskkill with /T kills child processes too
                result = subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                )
                return result.returncode == 0
            else:
                import signal
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                return True
        except ProcessLookupError:
            # Process already exited — that's fine
            return True
        except Exception as exc:
            print(f"[CleanupManager] Could not kill PID {pid}: {exc}")
            return False

    @staticmethod
    def delete_directory(directory: str) -> bool:
        """
        Recursively delete a directory.

        Returns True if the directory was removed (or didn't exist).
        """
        if not directory:
            return False
        if not os.path.exists(directory):
            return True
        try:
            shutil.rmtree(directory, ignore_errors=True)
            print(f"[CleanupManager] Deleted: {directory}")
            return True
        except Exception as exc:
            print(f"[CleanupManager] Could not delete {directory}: {exc}")
            return False

    @classmethod
    def full_cleanup(
        cls,
        pid: int = None,
        sandbox_dir: str = None,
        upload_dir: str = None,
    ) -> dict:
        """
        One-call cleanup: kill process + delete sandbox + delete upload.

        Returns
        -------
        dict  {"process_killed": bool, "sandbox_deleted": bool, "upload_deleted": bool}
        """
        proc = cls.kill_process(pid) if pid else False
        sb = cls.delete_directory(sandbox_dir) if sandbox_dir else False
        up = cls.delete_directory(upload_dir) if upload_dir else False

        print("[CleanupManager] Full cleanup complete.")
        return {
            "process_killed": proc,
            "sandbox_deleted": sb,
            "upload_deleted": up,
        }
