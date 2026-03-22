"""revkit core — general utilities."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

FILE_READ_CHUNK = 8192


def file_md5(path: str | Path) -> str | None:
    """Return hex MD5 digest of *path*, or None on error."""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            while chunk := f.read(FILE_READ_CHUNK):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def truncate(s: str, max_len: int = 200) -> str:
    """Truncate *s* to *max_len* chars, appending '...' if trimmed."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


DEFAULT_SCRIPTS_DIR = os.path.join(os.path.expanduser("~"), ".revkit", "scripts")


def resolve_script_path(code: str, engine: str, config: dict) -> str | None:
    """Resolve a .py script path with short-path support.

    Resolution order for ``code`` ending with ``.py``:
    1. Absolute path or starts with ./ ../ → use as-is
    2. Try ``{scripts_dir}/{engine}/{code}`` (e.g. ``analysis/find_crypto.py``)
    3. Try ``{scripts_dir}/{engine}/{code}`` with cwd fallback
    4. Return None if not found anywhere

    Returns the resolved absolute path, or None if not a .py file or not found.
    """
    if not code.endswith(".py"):
        return None

    # Absolute or explicit relative
    if os.path.isabs(code) or code.startswith("./") or code.startswith("../"):
        return code if os.path.isfile(code) else None

    # Already a valid path from cwd
    if os.path.isfile(code):
        return os.path.abspath(code)

    # Resolve under scripts_dir/engine/
    scripts_dir = config.get("paths", {}).get("scripts_dir", DEFAULT_SCRIPTS_DIR)
    scripts_dir = os.path.expanduser(scripts_dir)
    candidate = os.path.join(scripts_dir, engine, code)
    if os.path.isfile(candidate):
        return candidate

    return None
