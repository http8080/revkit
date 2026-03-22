#!/usr/bin/env python3
"""revkit automation helpers — shared utilities for all analysis scripts."""

import subprocess
import os
import sys
import json
import time
import atexit
from pathlib import Path

RK = ["python", "-m", "revkit.tools.cli.main"]

IDA_EXTS = frozenset({
    ".exe", ".dll", ".sys", ".so", ".dylib", ".elf", ".bin",
    ".o", ".ko", ".efi", ".mach", ".macho",
})
JEB_EXTS = frozenset({".apk", ".dex"})


def detect_engine(path: str) -> str:
    """Detect analysis engine from file extension."""
    ext = Path(path).suffix.lower()
    if ext in IDA_EXTS:
        return "ida"
    if ext in JEB_EXTS:
        return "jeb"
    raise ValueError(f"Unsupported file type: {ext} ({path})")


def run_rk(*args, timeout=60, remote=None):
    """Run revkit CLI command and return (stdout, returncode)."""
    cmd = list(RK)
    if remote:
        cmd += ["--remote", remote]
    cmd += list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return f"TIMEOUT ({timeout}s)", 1


def start_and_wait(engine, path, timeout=300, fresh=False, remote=None):
    """Start instance + wait for ready. Returns instance ID."""
    args = [engine, "start", path]
    if fresh and engine == "jeb":
        args.append("--fresh")
    out, rc = run_rk(*args, timeout=60, remote=remote)
    if rc != 0:
        raise RuntimeError(f"start failed: {out}")

    run_rk(engine, "wait", "--timeout", str(timeout),
           timeout=timeout + 20, remote=remote)

    # Extract IID from list
    list_out, _ = run_rk(engine, "list", remote=remote)
    stem = Path(path).stem.lower()
    for line in list_out.splitlines():
        if "|" in line and stem in line.lower() and "ID" not in line:
            iid = line.split("|")[1].strip()
            if iid:
                return iid
    return None


def stop_all(engine, remote=None):
    """Stop all instances for an engine."""
    list_out, _ = run_rk(engine, "list", remote=remote)
    for line in list_out.splitlines():
        if "|" in line and "ID" not in line:
            parts = line.split("|")
            if len(parts) > 1:
                iid = parts[1].strip()
                if iid:
                    run_rk(engine, "stop", "-i", iid,
                           timeout=60, remote=remote)


def ensure_clean(remote=None):
    """Stop all instances for both engines."""
    stop_all("ida", remote)
    stop_all("jeb", remote)


def setup_cleanup(remote=None):
    """Register atexit handler to clean up instances on crash."""
    atexit.register(ensure_clean, remote)
