"""revkit core — process management (spawn / kill).

Platform-aware detached process spawning for engine servers.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class SpawnConfig:
    """Configuration for spawning an engine server process."""
    cmd: list[str]
    cwd: str | Path | None = None
    env: dict[str, str] | None = None
    log_path: str | Path | None = None
    extra_flags: dict[str, Any] = field(default_factory=dict)


def detach_spawn(config: SpawnConfig) -> int:
    """Spawn a detached subprocess. Returns PID.

    - Windows: ``DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP``
    - Unix: ``start_new_session=True``
    """
    stderr_file = None
    stderr_target: Any = subprocess.DEVNULL
    if config.log_path:
        Path(config.log_path).parent.mkdir(parents=True, exist_ok=True)
        stderr_file = open(config.log_path, "ab")  # binary append for subprocess stderr
        stderr_target = stderr_file

    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": stderr_target,
        "cwd": str(config.cwd) if config.cwd else None,
        "env": config.env,
    }

    if sys.platform == "win32":
        flags = (
            subprocess.CREATE_NO_WINDOW
            | subprocess.CREATE_NEW_PROCESS_GROUP
        )
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True

    log.debug("detach_spawn: cmd=%s cwd=%s", config.cmd[:3], config.cwd)
    try:
        proc = subprocess.Popen(config.cmd, **kwargs)
    except Exception:
        # Close stderr file on spawn failure to prevent FD leak
        if stderr_file is not None:
            stderr_file.close()
        raise
    log.debug("detach_spawn: started PID %d", proc.pid)
    # Close our handle; the child process has its own copy of the fd
    if stderr_file is not None:
        stderr_file.close()
    return proc.pid


def force_kill(pid: int) -> bool:
    """Force-kill a process tree by PID. Returns True if killed."""
    if not pid:
        return False
    log.debug("force_kill: PID %d (with process tree)", pid)
    try:
        # Try psutil first — kills children recursively
        import psutil
        try:
            proc = psutil.Process(pid)
            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            proc.kill()
        except psutil.NoSuchProcess:
            pass
        return True
    except ImportError:
        pass
    try:
        if sys.platform == "win32":
            # /T = kill process tree, /F = force
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
            )
        else:
            os.kill(pid, signal.SIGKILL)
        return True
    except (OSError, ProcessLookupError):
        return False
