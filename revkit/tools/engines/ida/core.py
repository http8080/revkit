"""IDA engine core — shared helpers for ida/commands/*.

Adapter layer bridging revkit.tools.core (shared) to IDA-specific needs.
All cmd_* modules import from here: ``from ..core import ...``

Naming: public-facing helpers use underscore prefix (_log_ok, _rpc_call, …)
to keep them out of accidental * imports in other packages.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Shared core re-exports ────────────────────────────────

from ...core.config import load_config
from ...core.instance import (
    is_process_alive as _is_process_alive_raw,
    make_instance_id,
    resolve_instance as _resolve_instance_raw,
)
from ...core.output import (
    log_ok as _log_ok,
    log_err as _log_err,
    log_info as _log_info,
    log_warn as _log_warn,
    md_table_header as _md_table_header,
)
from ...core.process import SpawnConfig, detach_spawn, force_kill
from ...core.registry import (
    get_registry_path,
    registry_locked as _registry_locked_raw,
    load_registry as _load_registry_raw,
    save_registry as _save_registry_raw,
    cleanup_stale as _cleanup_stale_raw,
    register_instance as _register_instance_raw,
)
from ...core.rpc import post_rpc as _core_post_rpc, RpcError
from ...core.utils import file_md5, truncate as _truncate


# ── Architecture detection ────────────────────────────────

def arch_detect(binary_path: str, arch_override: str | None = None) -> dict:
    """Detect binary architecture from file header.

    Returns dict with keys: arch, bits, format, endian.
    """
    if arch_override:
        return {"arch": arch_override, "bits": None, "format": None, "endian": None}

    info: dict[str, Any] = {"arch": None, "bits": None, "format": None, "endian": "little"}
    try:
        with open(binary_path, "rb") as f:
            header = f.read(64)
    except OSError:
        return info

    # PE
    if header[:2] == b"MZ":
        info["format"] = "PE"
        # Read PE header offset at 0x3C
        if len(header) >= 0x40:
            pe_off = int.from_bytes(header[0x3C:0x40], "little")
            try:
                with open(binary_path, "rb") as f:
                    f.seek(pe_off)
                    pe_sig = f.read(6)
                if pe_sig[:4] == b"PE\0\0":
                    machine = int.from_bytes(pe_sig[4:6], "little")
                    _PE_MACHINES = {
                        0x14C: ("x86", 32), 0x8664: ("x86_64", 64),
                        0xAA64: ("ARM64", 64), 0x1C0: ("ARM", 32),
                    }
                    if machine in _PE_MACHINES:
                        info["arch"], info["bits"] = _PE_MACHINES[machine]
            except OSError:
                pass
        return info

    # ELF
    if header[:4] == b"\x7fELF":
        info["format"] = "ELF"
        info["bits"] = 64 if header[4] == 2 else 32
        info["endian"] = "big" if header[5] == 2 else "little"
        if len(header) >= 20:
            bo = "big" if info["endian"] == "big" else "little"
            machine = int.from_bytes(header[18:20], bo)
            _ELF_MACHINES = {
                3: "x86", 0x3E: "x86_64", 40: "ARM",
                0xB7: "ARM64", 8: "MIPS", 0x15: "PPC64",
            }
            info["arch"] = _ELF_MACHINES.get(machine)
        return info

    # Mach-O
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        info["format"] = "Mach-O"
        info["bits"] = 32
        return info
    if header[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        info["format"] = "Mach-O"
        info["bits"] = 64
        return info
    if header[:4] == b"\xca\xfe\xba\xbe":
        info["format"] = "FAT Mach-O"
        return info

    return info

# ── Optional third-party ──────────────────────────────────

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

try:
    import requests as req_lib
except ImportError:
    req_lib = None  # type: ignore[assignment]


# ── Constants ─────────────────────────────────────────────

SUPPORTED_BINARY_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".so", ".dylib", ".elf", ".bin",
    ".o", ".ko", ".efi", ".mach", ".macho",
})

STOP_WAIT_ITERATIONS = 10
STOP_POLL_INTERVAL = 0.5
STOP_RPC_TIMEOUT = 5.0
CLEANUP_AGE_SECONDS = 86400  # 24 h
PID_CREATE_TIME_TOLERANCE = 2.0

AUTO_GENERATED_PREFIXES = (
    "sub_", "loc_", "unk_", "off_",
    "byte_", "word_", "dword_", "qword_",
)
STRING_DISPLAY_LIMIT = 100


# ── IDA-specific registry path ────────────────────────────

_IDA_REGISTRY_PATH = get_registry_path("ida")


# ── Tiny helpers ──────────────────────────────────────────

def _opt(args: Any, key: str, default: Any = None) -> Any:
    """Safe ``getattr`` for ``argparse.Namespace``."""
    return getattr(args, key, default)


def _make_args(**kwargs: Any) -> argparse.Namespace:
    """Create a fake ``Namespace`` for internal dispatch."""
    return argparse.Namespace(**kwargs)


def _format_arch_info(arch_info: dict | None) -> str:
    if not arch_info:
        return "unknown"
    parts = []
    if arch_info.get("arch"):
        parts.append(arch_info["arch"])
    if arch_info.get("bits"):
        parts.append(f"{arch_info['bits']}-bit")
    if arch_info.get("format"):
        parts.append(arch_info["format"])
    return ", ".join(parts) or "unknown"


def _print_truncated(text: str, max_lines: int = 50) -> None:
    lines = text.splitlines()
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        print(f"\n... ({len(lines) - max_lines} more lines)")


# ── Registry wrappers (implicit IDA registry path) ────────

def _registry_locked():
    """Context manager — acquire/release IDA registry lock."""
    return _registry_locked_raw(_IDA_REGISTRY_PATH)


# Registry mtime cache — avoids repeated disk reads in polling loops
_registry_cache: dict | None = None
_registry_cache_mtime: float = 0.0


def load_registry() -> dict:
    """Load IDA registry as ``{instance_id: info_dict}``.
    Optimization: caches result and only re-reads from disk if file mtime changed."""
    global _registry_cache, _registry_cache_mtime
    try:
        mtime = os.path.getmtime(_IDA_REGISTRY_PATH)
    except OSError:
        return {}
    if _registry_cache is not None and mtime == _registry_cache_mtime:
        return dict(_registry_cache)  # Return copy to prevent mutation
    entries = _load_registry_raw(_IDA_REGISTRY_PATH)
    _registry_cache = {e["id"]: e for e in entries if "id" in e}
    _registry_cache_mtime = mtime
    return dict(_registry_cache)


def _invalidate_registry_cache():
    """Force next load_registry() to read from disk."""
    global _registry_cache, _registry_cache_mtime
    _registry_cache = None
    _registry_cache_mtime = 0.0


def save_registry(registry: dict) -> None:
    """Save IDA registry from ``{instance_id: info_dict}``."""
    _save_registry_raw(_IDA_REGISTRY_PATH, list(registry.values()))
    _invalidate_registry_cache()


def cleanup_stale(registry: dict, threshold: float = 120.0) -> None:
    """Remove stale entries from IDA registry."""
    _cleanup_stale_raw(_IDA_REGISTRY_PATH, threshold)


def resolve_instance(
    args: Any, config: dict,
) -> tuple[str | None, dict | None]:
    """Resolve IDA instance via -i / -b / single-active fallback."""
    stale = config.get("analysis", {}).get("stale_threshold", 120.0)
    return _resolve_instance_raw(args, _IDA_REGISTRY_PATH, stale)


# ── Process helpers ───────────────────────────────────────

def _is_process_alive(pid: int) -> bool:
    return _is_process_alive_raw(pid)


def _force_kill(
    iid: str, pid: int, create_time: float | None = None,
) -> None:
    """Force-kill an IDA server process and log it."""
    force_kill(pid)
    _log_info(f"Force-killed instance {iid} (PID {pid})")


# ── Auth token helpers ────────────────────────────────────

def _load_auth_token(config: dict, iid: str) -> str | None:
    """Read bearer token for *iid* from the token file.

    Token file format: ``instance_id:port:token`` per line.
    """
    token_path = config.get("security", {}).get("auth_token_file", "")
    if not token_path or not os.path.exists(token_path):
        log.debug("No auth token file for iid=%s", iid)
        return None
    try:
        with open(token_path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[0] == iid:
                    log.debug("Auth token loaded for iid=%s", iid)
                    return parts[2]
    except OSError as exc:
        log.warning("Failed to read auth token file %s: %s", token_path, exc)
    log.debug("No auth token entry found for iid=%s", iid)
    return None


def remove_auth_token(token_path: str, iid: str) -> None:
    """Remove all token entries for *iid* from the token file."""
    if not token_path or not os.path.exists(token_path):
        return
    try:
        with open(token_path, encoding="utf-8") as f:
            lines = f.readlines()
        cleaned = [l for l in lines if not l.strip().startswith(f"{iid}:")]
        with open(token_path, "w", encoding="utf-8") as f:
            f.writelines(cleaned)
        log.debug("Removed auth token for iid=%s", iid)
    except OSError as exc:
        log.warning("Failed to remove auth token for iid=%s: %s", iid, exc)


# ── IDB helpers ───────────────────────────────────────────

def get_idb_path(
    config: dict,
    binary_path: str,
    instance_id: str,
    force: bool = False,
    *,
    idb_dir: str | None = None,
) -> str:
    """Compute the .i64 database path for an instance."""
    base_dir = idb_dir or config.get("paths", {}).get(
        "idb_dir",
        os.path.join(str(Path.home()), ".revkit", "ida", "idb"),
    )
    os.makedirs(base_dir, exist_ok=True)
    basename = os.path.splitext(os.path.basename(binary_path))[0]
    return os.path.join(base_dir, f"{basename}_{instance_id}.i64")


def _load_idb_metadata(idb_path: str) -> dict:
    """Read ``.meta.json`` sidecar for an IDB."""
    meta_path = idb_path + ".meta.json"
    if not os.path.exists(meta_path):
        return {}
    try:
        with open(meta_path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


# ── RPC helpers ───────────────────────────────────────────

def post_rpc(
    config: dict,
    port: int,
    method: str,
    iid: str,
    params: dict | None = None,
    timeout: float | None = None,
    trace_id: str | None = None,
) -> dict:
    """Send a JSON-RPC request to an IDA server.

    Wraps ``core.rpc.post_rpc`` with IDA-specific URL/token resolution.
    """
    host = config.get("server", {}).get("host", "127.0.0.1")
    if host == "0.0.0.0":
        host = "127.0.0.1"  # bind-all → connect via loopback
    url = f"http://{host}:{port}/"
    token = _load_auth_token(config, iid)
    log.debug("post_rpc: method=%s url=%s iid=%s has_token=%s", method, url, iid, bool(token))
    try:
        t0 = time.time()
        result = _core_post_rpc(url, method, params, timeout=timeout,
                                auth_token=token, trace_id=trace_id)
        elapsed = (time.time() - t0) * 1000
        log.debug("post_rpc: method=%s -> OK (%.1fms)", method, elapsed)
        return result
    except RpcError as e:
        log.debug("post_rpc: method=%s -> error code=%s msg=%s", method, e.code, e.message)
        return {"error": {"code": e.code, "message": e.message}}


def _rpc_call(
    args: Any,
    config: dict,
    method: str,
    params: dict | None = None,
) -> dict | None:
    """High-level RPC call: resolve instance → post → return result.

    Returns the ``"result"`` dict, or ``None`` on failure.
    """
    iid, info = resolve_instance(args, config)
    if not iid:
        return None
    port = info.get("port")
    if not port:
        _log_err(f"Instance {iid} has no port (state: {info.get('state', '?')})")
        return None
    trace_id = getattr(args, '_trace_id', None) or getattr(args, 'trace_id', None)
    log.debug("_rpc_call: method=%s iid=%s port=%s params=%s", method, iid, port,
              list(params.keys()) if params else None)
    resp = post_rpc(config, port, method, iid, params, trace_id=trace_id)
    if "error" in resp:
        err = resp["error"]
        log.debug("_rpc_call: method=%s -> error: %s", method, err.get('message', str(err)))
        _log_err(f"RPC error: {err.get('message', str(err))}")
        return None
    result = resp.get("result")
    log.debug("_rpc_call: method=%s -> result keys=%s", method,
              list(result.keys()) if isinstance(result, dict) else type(result).__name__)
    return result


def _resolve_ready(
    args: Any, config: dict,
) -> tuple[str | None, dict | None, int | None]:
    """Resolve instance + verify ready state + return (iid, info, port)."""
    iid, info = resolve_instance(args, config)
    if not iid:
        return None, None, None
    if info.get("state") != "ready":
        _log_err(
            f"Instance {iid} not ready (state: {info.get('state', '?')})"
        )
        return None, None, None
    port = info.get("port")
    if not port:
        _log_err(f"Instance {iid} has no port")
        return None, None, None
    return iid, info, port


# ── Output / param helpers ────────────────────────────────

def _build_params(args: Any, mapping: dict[str, str]) -> dict:
    """Build RPC params from args via ``{arg_name: param_name}`` mapping."""
    p: dict[str, Any] = {}
    for arg_name, param_name in mapping.items():
        val = _opt(args, arg_name)
        if val is not None:
            p[param_name] = val
    return p


def _save_local(path: str, content: str) -> None:
    """Write *content* to a local file."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    _log_ok(f"Saved to: {path}")


def _is_md_out(args: Any) -> bool:
    """Check if output should be Markdown format."""
    out = _opt(args, "out", "")
    if out and out.endswith(".md"):
        return True
    return _opt(args, "markdown", False)


def _maybe_output_param(
    args: Any, params: dict, md_out: bool = False,
) -> None:
    """Add ``output`` param if ``--out`` is specified and not markdown."""
    out = _opt(args, "out")
    if out and not md_out:
        params["output"] = out


def _check_inline_limit(output: str, config: dict) -> tuple[str, bool]:
    """Truncate output if it exceeds ``output.inline_limit``."""
    limit = config.get("output", {}).get("inline_limit", 5000)
    if len(output) > limit:
        return (
            output[:limit] + f"\n\n... (truncated, {len(output)} chars total)",
            True,
        )
    return output, False


# ── Markdown formatters ───────────────────────────────────

def _md_decompile(r: dict, with_xrefs: bool = False) -> str:
    lines = [
        f"# {r.get('name', 'unknown')} @ {r.get('addr', '?')}",
        "",
        "```c",
        r.get("code", ""),
        "```",
    ]
    if with_xrefs:
        callers = r.get("callers", [])
        callees = r.get("callees", [])
        if callers:
            lines.extend(["", f"## Callers ({len(callers)})", ""])
            lines.append(_md_table_header("Address", "Name", "Type"))
            for c in callers:
                lines.append(
                    f"| {c['from_addr']} | {c['from_name']} | {c['type']} |"
                )
        if callees:
            lines.extend(["", f"## Callees ({len(callees)})", ""])
            lines.append(_md_table_header("Address", "Name", "Type"))
            for c in callees:
                lines.append(
                    f"| {c['to_addr']} | {c['to_name']} | {c['type']} |"
                )
    return "\n".join(lines)


def _md_decompile_batch(r: dict) -> str:
    lines = [
        "# Batch Decompile",
        "",
        f"Total: {r.get('total', 0)}, "
        f"Success: {r.get('success', 0)}, "
        f"Failed: {r.get('failed', 0)}",
        "",
    ]
    for func in r.get("functions", []):
        if "code" in func:
            lines.extend([
                f"## {func['name']} ({func['addr']})",
                "",
                "```c",
                func["code"],
                "```",
                "",
            ])
        else:
            lines.append(
                f"## {func.get('addr', '?')} — ERROR: {func.get('error', '?')}"
            )
            lines.append("")
    return "\n".join(lines)


def _md_summary(r: dict) -> str:
    lines = [
        f"# Binary Analysis Summary: {r.get('binary', '?')}",
        "",
        f"- **IDA**: {r.get('ida_version', '?')}",
        f"- **Decompiler**: {r.get('decompiler', '?')}",
        f"- **Functions**: {r.get('func_count', 0)} "
        f"(avg size: {r.get('avg_func_size', 0)} bytes)",
        f"- **Strings**: {r.get('total_strings', 0)}",
        f"- **Imports**: {r.get('total_imports', 0)}",
        f"- **Exports**: {r.get('export_count', 0)}",
    ]
    segs = r.get("segments", [])
    if segs:
        lines.extend([
            "",
            "## Segments",
            "",
            _md_table_header("Range", "Name", "Size", "Perm"),
        ])
        for s in segs:
            lines.append(
                f"| {s['start_addr']}-{s['end_addr']} "
                f"| {s.get('name', '')} | {s['size']} | {s['perm']} |"
            )
    return "\n".join(lines)


# ── Instance lifecycle ────────────────────────────────────

def _register_instance(
    config: dict,
    iid: str,
    binary_path: str,
    arch_info: dict | None,
    idb_path: str,
    log_path: str,
    force: bool = False,
) -> bool:
    """Register a new IDA instance in the registry."""
    from .engine import IDAEngine

    engine = IDAEngine()
    entry = engine.build_initial_registry_entry(
        iid,
        binary_path,
        arch=arch_info.get("arch") if arch_info else None,
        bits=arch_info.get("bits") if arch_info else None,
        file_format=arch_info.get("format") if arch_info else None,
        idb_path=idb_path,
        log_path=log_path,
    )
    try:
        _register_instance_raw(
            _IDA_REGISTRY_PATH,
            entry,
            max_instances=config.get("limits", {}).get("max_instances", 5),
        )
        return True
    except RuntimeError as e:
        if force:
            registry = load_registry()
            for rid, rinfo in list(registry.items()):
                if os.path.normcase(
                    rinfo.get("path", "")
                ) == os.path.normcase(binary_path):
                    del registry[rid]
            save_registry(registry)
            try:
                _register_instance_raw(_IDA_REGISTRY_PATH, entry)
                return True
            except RuntimeError as e2:
                _log_err(str(e2))
                return False
        _log_err(str(e))
        return False


def _spawn_server(
    config: dict,
    config_path: str,
    binary_path: str,
    iid: str,
    idb_path: str,
    log_path: str,
    fresh: bool = False,
) -> Any:
    """Spawn an IDA headless server process. Returns process-like object."""
    from .engine import IDAEngine

    engine = IDAEngine()
    spawn_cfg = engine.build_spawn_config(
        config,
        binary_path,
        iid,
        config_path=config_path,
        idb_path=idb_path,
        log_path=log_path,
        fresh=fresh,
    )
    engine.pre_spawn(config, spawn_cfg)
    pid = detach_spawn(spawn_cfg)

    # Update registry with PID
    with _registry_locked():
        reg = load_registry()
        if iid in reg:
            reg[iid]["pid"] = pid
            save_registry(reg)

    class _Proc:
        pass

    proc = _Proc()
    proc.pid = pid  # type: ignore[attr-defined]
    return proc


def _wait_for_start(iid: str, timeout: float = 120.0) -> str:
    """Poll registry until instance reaches 'ready' or 'error' state.

    Returns the final state string.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        registry = load_registry()
        info = registry.get(iid)
        if not info:
            return "not_found"
        state = info.get("state", "unknown")
        if state in ("ready", "error"):
            return state
        time.sleep(0.5)
    return "timeout"
