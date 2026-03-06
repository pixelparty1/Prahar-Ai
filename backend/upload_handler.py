"""
upload_handler.py
-----------------
Handles user-uploaded ZIP files containing website source code.

Responsibilities:
  - Accept a ZIP file path
  - Validate file type and size
  - Extract to a unique temporary folder: /tmp/uploads/project_<uuid>/
  - Return the extracted project directory path
"""

import os
import uuid
import zipfile
import tempfile
import shutil

# ── Configuration ─────────────────────────────────────────────────────────

UPLOAD_BASE_DIR = os.path.join(tempfile.gettempdir(), "uploads")
MAX_ZIP_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


class UploadHandler:
    """Accept, validate, and extract uploaded ZIP files."""

    def __init__(self):
        os.makedirs(UPLOAD_BASE_DIR, exist_ok=True)

    def handle_zip(self, zip_path: str) -> dict:
        """
        Validate and extract a ZIP file.

        Parameters
        ----------
        zip_path : str
            Absolute path to the ZIP file on disk.

        Returns
        -------
        dict
            {
                "success": bool,
                "project_dir": str or None,   # extracted folder path
                "upload_id": str or None,
                "error": str or None,
            }
        """
        # 1 — File must exist
        if not os.path.isfile(zip_path):
            return self._error(f"File not found: {zip_path}")

        # 2 — Must be a .zip
        if not zip_path.lower().endswith(".zip"):
            return self._error("Only .zip files are accepted.")

        # 3 — Size check
        size = os.path.getsize(zip_path)
        if size > MAX_ZIP_SIZE_BYTES:
            return self._error(
                f"File too large ({size / 1024 / 1024:.1f} MB). "
                f"Max allowed: {MAX_ZIP_SIZE_BYTES / 1024 / 1024:.0f} MB."
            )

        # 4 — Must be a real ZIP
        if not zipfile.is_zipfile(zip_path):
            return self._error("File is not a valid ZIP archive.")

        # 5 — Security: reject path-traversal entries
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                normalized = os.path.normpath(member.filename)
                if normalized.startswith("..") or os.path.isabs(normalized):
                    return self._error(f"ZIP contains unsafe path: {member.filename}")

        # 6 — Extract to unique temp folder
        upload_id = uuid.uuid4().hex[:12]
        project_dir = os.path.join(UPLOAD_BASE_DIR, f"project_{upload_id}")

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(project_dir)
        except Exception as exc:
            if os.path.exists(project_dir):
                shutil.rmtree(project_dir, ignore_errors=True)
            return self._error(f"Extraction failed: {exc}")

        # 7 — If the ZIP had a single root folder, step into it
        project_dir = self._unwrap_single_dir(project_dir)

        print(f"[UploadHandler] Extracted to: {project_dir}  (id={upload_id})")
        return {
            "success": True,
            "project_dir": project_dir,
            "upload_id": upload_id,
            "error": None,
        }

    # ── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _error(msg: str) -> dict:
        return {"success": False, "project_dir": None, "upload_id": None, "error": msg}

    @staticmethod
    def _unwrap_single_dir(path: str) -> str:
        """If extraction produced one top-level directory, return it."""
        entries = os.listdir(path)
        if len(entries) == 1:
            child = os.path.join(path, entries[0])
            if os.path.isdir(child):
                return child
        return path
