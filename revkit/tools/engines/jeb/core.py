"""JEB engine core — shared helpers for jeb/commands/*.

Adapter layer bridging revkit.tools.core (shared) to JEB-specific needs.
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

STOP_WAIT_ITERATIONS = 10
STOP_POLL_INTERVAL = 0.5
STOP_RPC_TIMEOUT = 5.0
CLEANUP_AGE_SECONDS = 86400  # 24 h

STRING_DISPLAY_LIMIT = 100

# Param mapping for list-style RPC commands (classes, strings, etc.)
_LIST_PARAM_MAP: dict[str, str] = {
    "offset": "offset",
    "limit": "limit",
}


# ── JEB-specific registry path ───────────────────────────

_JEB_REGISTRY_PATH = get_registry_path("jeb")


# ── Tiny helpers ─────────────────────────────────────────

def _opt(args: Any, key: str, default: Any = None) -> Any:
    """Safe ``getattr`` for ``argparse.Namespace``."""
    return getattr(args, key, default)


def _make_args(**kwargs: Any) -> argparse.Namespace:
    """Create a fake ``Namespace`` for internal dispatch."""
    return argparse.Namespace(**kwargs)


def _print_truncated(text: str, max_lines: int = 50) -> None:
    lines = text.splitlines()
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        print(f"\n... ({len(lines) - max_lines} more lines)")


def _get_launcher_name() -> str:
    """Return the platform-specific JEB launcher name."""
    from .engine import JEBEngine
    return JEBEngine._get_launcher_name()


def make_instance_id(binary_path: str) -> str:
    """Create a JEB instance ID from binary path."""
    from .engine import JEBEngine
    engine = JEBEngine()
    return engine.make_instance_id(binary_path)


# ── Registry wrappers (implicit JEB registry path) ───────

def _registry_locked():
    """Context manager — acquire/release JEB registry lock."""
    return _registry_locked_raw(_JEB_REGISTRY_PATH)


def load_registry() -> dict:
    """Load JEB registry as ``{instance_id: info_dict}``."""
    entries = _load_registry_raw(_JEB_REGISTRY_PATH)
    return {e["id"]: e for e in entries if "id" in e}


def save_registry(registry: dict) -> None:
    """Save JEB registry from ``{instance_id: info_dict}``."""
    _save_registry_raw(_JEB_REGISTRY_PATH, list(registry.values()))


def cleanup_stale(registry: dict, threshold: float = 120.0) -> None:
    """Remove stale entries from JEB registry."""
    _cleanup_stale_raw(_JEB_REGISTRY_PATH, threshold)


def resolve_instance(
    args: Any, config: dict,
) -> tuple[str | None, dict | None]:
    """Resolve JEB instance via -i / -b / single-active fallback."""
    stale = config.get("analysis", {}).get("stale_threshold", 120.0)
    return _resolve_instance_raw(args, _JEB_REGISTRY_PATH, stale)


# ── Process helpers ──────────────────────────────────────

def _is_process_alive(pid: int) -> bool:
    return _is_process_alive_raw(pid)


def _force_kill(
    iid: str, pid: int, create_time: float | None = None,
) -> None:
    """Force-kill a JEB server process and log it."""
    force_kill(pid)
    _log_info(f"Force-killed instance {iid} (PID {pid})")


def _cleanup_instance(config: dict, iid: str) -> None:
    """Remove instance from registry and clean up auth token."""
    try:
        with _registry_locked():
            reg = load_registry()
            reg.pop(iid, None)
            save_registry(reg)
    except RuntimeError:
        pass
    remove_auth_token(config.get("security", {}).get("auth_token_file", ""), iid)


# ── Auth token helpers ───────────────────────────────────

_auth_token_cache: dict[str, str] = {}  # iid -> token


def _load_auth_token(config: dict, iid: str) -> str | None:
    """Read bearer token for *iid* from the token file.

    Token file format: ``instance_id:port:token`` per line.
    Uses a module-level cache to avoid re-reading the file on every RPC call.
    """
    if iid in _auth_token_cache:
        log.debug("Auth token cache hit for iid=%s", iid)
        return _auth_token_cache[iid]

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
                    token = parts[2]
                    _auth_token_cache[iid] = token
                    return token
    except OSError as exc:
        log.warning("Failed to read auth token file %s: %s", token_path, exc)
    log.debug("No auth token entry found for iid=%s", iid)
    return None


def remove_auth_token(token_path: str, iid: str) -> None:
    """Remove all token entries for *iid* from the token file."""
    _auth_token_cache.pop(iid, None)  # invalidate cache
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


# ── RPC helpers ──────────────────────────────────────────

def post_rpc(
    config: dict,
    port: int,
    method: str,
    iid: str,
    params: dict | None = None,
    timeout: float | None = None,
    trace_id: str | None = None,
) -> dict:
    """Send a JSON-RPC request to a JEB server.

    Wraps ``core.rpc.post_rpc`` with JEB-specific URL/token resolution.
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
    timeout: float | None = None,
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
    resp = post_rpc(config, port, method, iid, params, timeout=timeout, trace_id=trace_id)
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


# ── Output / param helpers ───────────────────────────────

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
    return _opt(args, "md_out", False) or _opt(args, "markdown", False)


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


# ── Markdown formatters ──────────────────────────────────

def _md_decompile(r: dict, with_xrefs: bool = False) -> str:
    sig = r.get("class_sig", r.get("sig", r.get("name", "unknown")))
    lines = [
        f"# {sig}",
        "",
        "```java",
        r.get("code", ""),
        "```",
    ]
    if with_xrefs:
        callers = r.get("callers", [])
        callees = r.get("callees", [])
        if callers:
            lines.extend(["", f"## Callers ({len(callers)})", ""])
            lines.append(_md_table_header("Signature", "Type"))
            for c in callers:
                lines.append(
                    f"| {c.get('method_sig', '')} | {c.get('type', '')} |"
                )
        if callees:
            lines.extend(["", f"## Callees ({len(callees)})", ""])
            lines.append(_md_table_header("Signature", "Type"))
            for c in callees:
                lines.append(
                    f"| {c.get('method_sig', '')} | {c.get('type', '')} |"
                )
    return "\n".join(lines)


def _md_summary(r: dict) -> str:
    lines = [
        f"# Analysis Summary: {r.get('binary', '?')}",
        "",
        f"- **JEB**: {r.get('jeb_version', '?')}",
        f"- **Classes**: {r.get('class_count', 0)}",
        f"- **Methods**: {r.get('method_count', 0)}",
        f"- **Native**: {r.get('native_method_count', 0)}",
        f"- **Strings**: {r.get('string_count', 0)}",
        f"- **DEX files**: {r.get('dex_count', 0)}",
        f"- **Permissions**: {r.get('permission_count', 0)}",
    ]
    apk_info = r.get("apk_info") or {}
    pkg = apk_info.get("package") or r.get("package_name")
    if pkg:
        lines.append(f"- **Package**: {pkg}")
    act = apk_info.get("main_activity") or r.get("main_activity")
    if act:
        lines.append(f"- **Main Activity**: {act}")
    if apk_info.get("min_sdk"):
        lines.append(f"- **Min SDK**: {apk_info['min_sdk']}")
    if apk_info.get("target_sdk"):
        lines.append(f"- **Target SDK**: {apk_info['target_sdk']}")
    return "\n".join(lines)


# ── Instance lifecycle ───────────────────────────────────

def _register_instance(
    config: dict,
    iid: str,
    binary_path: str,
    project_path: str,
    log_path: str,
    force: bool = False,
) -> bool:
    """Register a new JEB instance in the registry."""
    from .engine import JEBEngine

    engine = JEBEngine()
    entry = engine.build_initial_registry_entry(
        iid,
        binary_path,
        project_path=project_path,
        log_path=log_path,
    )
    try:
        _register_instance_raw(
            _JEB_REGISTRY_PATH,
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
                _register_instance_raw(_JEB_REGISTRY_PATH, entry)
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
    project_path: str,
    log_path: str,
    fresh: bool = False,
    *,
    xmx: str | None = None,
) -> Any:
    """Spawn a JEB headless server process. Returns process-like object."""
    from .engine import JEBEngine

    engine = JEBEngine()
    spawn_cfg = engine.build_spawn_config(
        config,
        binary_path,
        iid,
        config_path=config_path,
        project_path=project_path,
        log_path=log_path,
        fresh=fresh,
        xmx=xmx,
    )
    engine.pre_spawn(config, spawn_cfg, binary_path=binary_path, xmx=xmx)
    spawn_method = config.get("jeb", {}).get("spawn_method", "wrapper")
    log.info("_spawn_server: iid=%s spawn_method=%s binary=%s",
             iid, spawn_method, os.path.basename(binary_path))
    pid = detach_spawn(spawn_cfg)

    # Update registry with PID
    try:
        with _registry_locked():
            reg = load_registry()
            if iid in reg:
                reg[iid]["pid"] = pid
                save_registry(reg)
    except RuntimeError:
        pass

    class _Proc:
        pass

    proc = _Proc()
    proc.pid = pid  # type: ignore[attr-defined]
    return proc


def _wait_for_start(config: dict, iid: str, timeout: float = 120.0) -> str:
    """Poll registry until instance reaches 'ready' or 'error' state.

    Returns the final state string.
    """
    poll = config.get("analysis", {}).get("wait_poll_interval", 2.0)
    deadline = time.time() + timeout
    while time.time() < deadline:
        registry = load_registry()
        info = registry.get(iid)
        if not info:
            return "not_found"
        state = info.get("state", "unknown")
        if state in ("ready", "error"):
            return state
        time.sleep(poll)
    return "timeout"
