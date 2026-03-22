"""revkit core — output formatting and JSON envelope.

Controls verbose/quiet/json modes (D4: module-level variables).
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

_quiet = False
_verbose = False
_json_mode = False


def set_output_mode(*, quiet: bool = False, verbose: bool = False) -> None:
    global _quiet, _verbose
    _quiet = quiet
    _verbose = verbose


def init_json_mode() -> None:
    """Enable JSON mode — redirect non-JSON output to stderr."""
    global _json_mode
    _json_mode = True


def is_verbose() -> bool:
    return _verbose


# ── log helpers ───────────────────────────────────────────

def _out(prefix: str, msg: str) -> None:
    dest = sys.stderr if _json_mode else sys.stdout
    print(f"{prefix} {msg}", file=dest)


def log_ok(msg: str) -> None:
    if not _quiet:
        _out("[+]", msg)


def log_err(msg: str) -> None:
    _out("[-]", msg)


def log_info(msg: str) -> None:
    if not _quiet:
        _out("[*]", msg)


def log_warn(msg: str) -> None:
    _out("[!]", msg)


def log_verbose(msg: str) -> None:
    if _verbose:
        _out("[.]", msg)


# ── JSON envelope (D13: elapsed_ms + truncated) ──────────

def json_success(
    engine: str,
    command: str,
    data: Any,
    *,
    instance_id: str | None = None,
    elapsed_ms: float | None = None,
    truncated: bool = False,
) -> dict:
    """Build a success JSON envelope."""
    resp: dict[str, Any] = {
        "ok": True,
        "engine": engine,
        "command": command,
        "data": data,
    }
    if instance_id:
        resp["instance_id"] = instance_id
    if elapsed_ms is not None:
        resp["elapsed_ms"] = round(elapsed_ms, 2)
    if truncated:
        resp["truncated"] = True
    return resp


def json_error(
    engine: str,
    command: str,
    code: str,
    message: str,
    *,
    error_type: str = "error",
    suggestion: str | None = None,
    instance_id: str | None = None,
) -> dict:
    """Build an error JSON envelope."""
    err: dict[str, Any] = {
        "code": code,
        "type": error_type,
        "message": message,
    }
    if suggestion:
        err["suggestion"] = suggestion
    return {
        "ok": False,
        "engine": engine,
        "command": command,
        "error": err,
        "instance_id": instance_id,
    }


# ── Markdown table helper ────────────────────────────────

def md_table_header(*headers: str) -> str:
    """Return a Markdown table header + separator line."""
    hdr = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    return f"{hdr}\n{sep}"
