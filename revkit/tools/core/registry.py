"""revkit core — instance registry + file lock.

Manages per-engine registry files at ``~/.revkit/{engine}/registry.json``.
All functions receive *registry_path* explicitly (D17 — no module globals).
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_LOCK_TIMEOUT = 5.0
STALE_LOCK_TIMEOUT = 10.0
LOCK_POLL_INTERVAL = 0.1
DEFAULT_STALE_THRESHOLD = 120.0
INIT_STALE_TIMEOUT = 300.0


# ── path helpers ──────────────────────────────────────────

def get_registry_path(engine_name: str) -> Path:
    """Return ``~/.revkit/{engine}/registry.json``."""
    return Path.home() / ".revkit" / engine_name / "registry.json"


def _lock_path_for(registry_path: Path) -> Path:
    return registry_path.with_suffix(".json.lock")


# ── file lock (O_CREAT|O_EXCL, cross-platform) ───────────

def acquire_lock(
    lock_path: str | Path, timeout: float = DEFAULT_LOCK_TIMEOUT
) -> bool:
    """Acquire an exclusive file lock. Returns True on success."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(str(lock_path))
                if age > STALE_LOCK_TIMEOUT:
                    log.warning("Removing stale lock (age=%.1fs): %s", age, lock_path)
                    os.remove(str(lock_path))
                    continue
            except OSError:
                pass
            time.sleep(LOCK_POLL_INTERVAL)
    log.warning("Lock acquisition timed out: %s", lock_path)
    return False


def release_lock(lock_path: str | Path) -> None:
    """Release the file lock."""
    try:
        os.remove(str(lock_path))
    except OSError:
        pass


@contextmanager
def registry_locked(registry_path: str | Path):
    """Context manager — acquire/release lock around registry operations."""
    lp = _lock_path_for(Path(registry_path))
    if not acquire_lock(lp):
        raise RuntimeError(f"Could not acquire registry lock: {lp}")
    try:
        yield
    finally:
        release_lock(lp)


# ── registry I/O ─────────────────────────────────────────

def load_registry(registry_path: str | Path) -> list[dict]:
    """Read registry JSON. Returns ``[]`` if file missing or corrupt."""
    registry_path = Path(registry_path)
    if not registry_path.exists():
        log.debug("Registry file not found: %s", registry_path)
        return []
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            entries = list(data.values())
        elif isinstance(data, list):
            entries = data
        else:
            log.warning("Registry has unexpected type %s, returning empty", type(data).__name__)
            return []
        log.debug("Loaded %d entries from %s", len(entries), registry_path)
        return entries
    except json.JSONDecodeError as exc:
        log.warning("Corrupt registry JSON at %s: %s", registry_path, exc)
        return []
    except OSError as exc:
        log.warning("Cannot read registry %s: %s", registry_path, exc)
        return []


def save_registry(registry_path: str | Path, entries: list[dict]) -> None:
    """Write registry entries to JSON."""
    registry_path = Path(registry_path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    log.debug("Saving %d entries to %s", len(entries), registry_path)
    registry_path.write_text(
        json.dumps(entries, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ── stale cleanup (D1: common, default ON) ────────────────

def _is_process_alive(entry: dict) -> bool:
    """Check if the process recorded in *entry* is still running.

    Uses psutil when available (required on Windows where os.kill(pid, 0)
    fails for detached processes). Falls back to os.kill on Unix.
    """
    pid = entry.get("pid")
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


def cleanup_stale(
    registry_path: str | Path,
    stale_threshold: float = DEFAULT_STALE_THRESHOLD,
) -> list[dict]:
    """Remove entries whose process is dead or heartbeat expired.

    Acquires registry lock to prevent race conditions with concurrent
    register_instance/unregister_instance calls.
    """
    registry_path = Path(registry_path)
    lp = _lock_path_for(registry_path)
    got_lock = acquire_lock(lp, timeout=2.0)
    # Proceed even without lock (best-effort cleanup), but log warning
    if not got_lock:
        log.warning("cleanup_stale: could not acquire lock, proceeding unlocked")
    try:
        return _cleanup_stale_impl(registry_path, stale_threshold)
    finally:
        if got_lock:
            release_lock(lp)


def _cleanup_stale_impl(
    registry_path: Path,
    stale_threshold: float,
) -> list[dict]:
    """Internal cleanup implementation (caller holds lock)."""
    entries = load_registry(registry_path)
    now = time.time()
    alive = []
    removed = []
    for entry in entries:
        state = entry.get("state", "unknown")
        iid = entry.get("id", "?")
        if state == "initializing":
            if now - entry.get("started", 0) > INIT_STALE_TIMEOUT:
                removed.append((iid, "init_timeout"))
                continue
        if state == "error":
            if not _is_process_alive(entry):
                removed.append((iid, "error_dead"))
                continue
        hb = entry.get("last_heartbeat")
        if hb and now - hb > stale_threshold:
            if not _is_process_alive(entry):
                removed.append((iid, "heartbeat_expired"))
                continue
            else:
                # Process alive but heartbeat expired → kill hung process
                pid = entry.get("pid")
                if pid:
                    from .process import force_kill
                    force_kill(pid)
                    log.warning("cleanup_stale: killed hung process PID %d (heartbeat expired for %s)", pid, iid)
                removed.append((iid, "heartbeat_expired_killed"))
                continue
        if not hb and not _is_process_alive(entry) and entry.get("pid"):
            removed.append((iid, "process_dead"))
            continue
        alive.append(entry)
    if removed:
        log.debug("cleanup_stale: removed %d entries: %s", len(removed), removed)
        save_registry(registry_path, alive)
    return alive


# ── register / unregister ─────────────────────────────────

def register_instance(
    registry_path: str | Path,
    entry: dict,
    max_instances: int = 5,
) -> None:
    """Register a new instance. Auto-cleans stale entries first (D1).

    Raises:
        RuntimeError: max instances exceeded or duplicate active binary.
    """
    registry_path = Path(registry_path)
    with registry_locked(registry_path):
        entries = cleanup_stale(registry_path)
        if len(entries) >= max_instances:
            raise RuntimeError(
                f"Max instances reached ({max_instances})"
            )
        binary = os.path.normcase(entry.get("path", ""))
        for e in entries:
            if (os.path.normcase(e.get("path", "")) == binary
                    and e.get("state") in ("analyzing", "ready")):
                raise RuntimeError(
                    f"{os.path.basename(binary)} already running "
                    f"(id: {e['id']}). Use --force."
                )
        entries.append(entry)
        save_registry(registry_path, entries)


def unregister_instance(
    registry_path: str | Path, instance_id: str
) -> bool:
    """Remove an instance by ID. Returns True if found and removed."""
    registry_path = Path(registry_path)
    with registry_locked(registry_path):
        entries = load_registry(registry_path)
        new_entries = [e for e in entries if e.get("id") != instance_id]
        if len(new_entries) == len(entries):
            return False
        save_registry(registry_path, new_entries)
        return True
