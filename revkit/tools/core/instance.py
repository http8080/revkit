"""revkit core — instance ID generation and resolution.

resolve_instance uses 3-tier fallback: -i <id> → -b <hint> → single active.
Includes auto cleanup_stale on resolve (D1: common, default ON).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from .output import log_err, log_verbose
from .registry import cleanup_stale, load_registry

log = logging.getLogger(__name__)

INSTANCE_ID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
INSTANCE_ID_LENGTH = 4
ACTIVE_STATES = frozenset({"ready", "analyzing"})
DEFAULT_POLL_INTERVAL = 0.5


def is_process_alive(pid: int) -> bool:
    """Check if *pid* is still running (cross-platform).

    Uses psutil when available (required on Windows for detached processes).
    Falls back to os.kill(pid, 0) on Unix.
    """
    if not pid:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def make_instance_id(binary_path: str) -> str:
    """Generate a human-friendly instance ID.

    Format: ``{sanitized_name}_{hash4}``
    e.g. ``uncrackable-level3_a1b2``
    """
    basename = os.path.splitext(os.path.basename(binary_path))[0]
    clean = re.sub(r"[^a-z0-9-]", "-", basename.lower())
    clean = re.sub(r"-+", "-", clean).strip("-")
    if len(clean) > 20:
        clean = clean[:20].rstrip("-")

    raw = f"{binary_path}{time.time()}{os.getpid()}"
    h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
    base = len(INSTANCE_ID_CHARS)
    suffix = ""
    for _ in range(INSTANCE_ID_LENGTH):
        suffix = INSTANCE_ID_CHARS[h % base] + suffix
        h //= base
    return f"{clean}_{suffix}" if clean else suffix


def resolve_instance(
    args: Any,
    registry_path: str | Path,
    stale_threshold: float = 120.0,
) -> tuple[str | None, dict | None]:
    """Resolve target instance via 3-tier fallback.

    1. ``-i <instance_id>`` — exact match
    2. ``-b <binary_hint>`` — substring match on binary name
    3. Single active instance — auto-select

    Returns ``(instance_id, info_dict)`` or ``(None, None)``.
    """
    entries = cleanup_stale(registry_path, stale_threshold)
    registry = {e["id"]: e for e in entries if "id" in e}
    log.debug("resolve_instance: %d entries after stale cleanup", len(registry))

    iid = getattr(args, "instance", None)
    if iid:
        log.debug("resolve tier 1: explicit -i %s", iid)
        if iid in registry:
            return iid, registry[iid]
        log_err(f"Instance '{iid}' not found")
        return None, None

    hint = getattr(args, "binary_hint", None)
    if hint:
        log.debug("resolve tier 2: binary hint '%s'", hint)
        matches = [
            (k, v)
            for k, v in registry.items()
            if hint.lower() in v.get("binary", "").lower()
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            log_err(f"No instance matching '{hint}'")
        else:
            log_err(f"Multiple instances match '{hint}':")
            for k, v in matches:
                print(f"  {k}  {v.get('binary', '?')}")
        return None, None

    active = {k: v for k, v in registry.items() if v.get("state") in ACTIVE_STATES}
    log.debug("resolve tier 3: %d active instances", len(active))
    if len(active) == 1:
        k = next(iter(active))
        return k, active[k]
    if not active:
        log_err("No active instances. Use 'start' first.")
    else:
        log_err("Multiple active instances. Use -i <id> to select:")
        for k, v in active.items():
            print(f"  {k}  {v.get('state', '?'):<12}  {v.get('binary', '?')}")
    return None, None


def wait_for_start(
    registry_path: str | Path,
    instance_id: str,
    timeout: float = 120.0,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
) -> bool:
    """Poll registry until *instance_id* reaches 'ready' state."""
    log.debug("wait_for_start: iid=%s timeout=%.1fs poll=%.1fs", instance_id, timeout, poll_interval)
    deadline = time.time() + timeout
    while time.time() < deadline:
        entries = load_registry(registry_path)
        for e in entries:
            if e.get("id") == instance_id:
                state = e.get("state", "")
                log.debug("wait_for_start: iid=%s state=%s", instance_id, state)
                if state == "ready":
                    return True
                if state == "error":
                    log_err(f"Instance {instance_id} entered error state")
                    return False
                break
        time.sleep(poll_interval)
    # Kill orphaned process on timeout to prevent leaks
    entries = load_registry(registry_path)
    for e in entries:
        if e.get("id") == instance_id:
            pid = e.get("pid")
            if pid and is_process_alive(pid):
                from .process import force_kill
                force_kill(pid)
                log.warning("wait_for_start: killed orphaned PID %d after timeout", pid)
            break
    log_err(f"Timeout waiting for {instance_id} ({timeout}s) — process killed")
    return False
