"""Modification API — rename, comment, type, save, patch, exec."""

import contextlib
import io

from .. import framework as _fw
from ..framework import (
    RpcError, _fmt_addr, _require_param, _resolve_addr,
    _parse_and_apply_type, _bytes_to_hex,
    _maybe_save_db, save_db, _save_output,
    invalidate_func_name_cache, invalidate_decompile_cache,
)


def _handle_rename_batch(params):
    """Batch rename from list of addr/name pairs."""
    import idc
    entries = _require_param(params, "entries")
    if not isinstance(entries, list):
        raise RpcError("INVALID_PARAM", "entries must be a list of {addr, name} objects")
    results = {"total": len(entries), "success": 0, "failed": 0, "renames": []}
    for entry in entries:
        addr_str = entry.get("addr")
        name = entry.get("name")
        if not addr_str or not name:
            results["failed"] += 1
            results["renames"].append({"addr": str(addr_str), "name": str(name), "ok": False, "error": "missing addr or name"})
            continue
        try:
            ea = _resolve_addr(addr_str)
            ok = idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)
            if ok:
                results["success"] += 1
                results["renames"].append({"addr": _fmt_addr(ea), "name": name, "ok": True})
            else:
                results["failed"] += 1
                results["renames"].append({"addr": _fmt_addr(ea), "name": name, "ok": False, "error": "set_name failed"})
        except Exception as e:
            results["failed"] += 1
            results["renames"].append({"addr": str(addr_str), "name": str(name), "ok": False, "error": str(e)})
    if results["success"] > 0:
        invalidate_func_name_cache()  # Batch rename — clear entire cache
        invalidate_decompile_cache()
        _maybe_save_db()
    return results


def _handle_set_name(params):
    import idc
    ea = _resolve_addr(params.get("addr"))
    name = _require_param(params, "name")
    ok = idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)
    if not ok:
        raise RpcError("SET_NAME_FAILED", f"Cannot set name at {_fmt_addr(ea)}")
    invalidate_func_name_cache(ea)
    invalidate_decompile_cache(ea)
    _maybe_save_db()
    return {"ok": True, "addr": _fmt_addr(ea), "name": name}


def _handle_set_comment(params):
    import idc
    ea = _resolve_addr(params.get("addr"))
    comment = params.get("comment", "")
    repeatable = params.get("repeatable", False)
    cmt_type = params.get("type", "line")
    if cmt_type == "func":
        ok = idc.set_func_cmt(ea, comment, repeatable)
    else:
        ok = idc.set_cmt(ea, comment, repeatable)
    if ok == 0 and comment:
        raise RpcError("SET_COMMENT_FAILED", f"Cannot set comment at {_fmt_addr(ea)}")
    _maybe_save_db()
    return {"ok": True, "addr": _fmt_addr(ea)}


def _handle_get_comments(params):
    import idc
    ea = _resolve_addr(params.get("addr"))
    return {
        "addr": _fmt_addr(ea),
        "comment": idc.get_cmt(ea, False) or "",
        "repeatable_comment": idc.get_cmt(ea, True) or "",
        "func_comment": idc.get_func_cmt(ea, False) or "",
    }


def _handle_set_type(params):
    ea = _resolve_addr(params.get("addr"))
    type_str = _require_param(params, "type")
    tif = _parse_and_apply_type(ea, type_str)
    invalidate_decompile_cache(ea)  # Type change affects decompile output
    _maybe_save_db()
    return {"ok": True, "addr": _fmt_addr(ea), "type": str(tif)}


def _handle_save_db(params):
    import ida_loader
    ok = save_db()
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return {"ok": bool(ok), "idb_path": idb}


def _handle_patch_bytes(params):
    """Patch bytes at an address."""
    import ida_bytes, idc
    if not _fw._config.get("security", {}).get("exec_enabled", False):
        raise RpcError("PATCH_DISABLED",
                        "Patching requires security.exec_enabled=true",
                        suggestion="Set security.exec_enabled to true in config.json")
    ea = _resolve_addr(params.get("addr"))
    hex_str = _require_param(params, "bytes", "bytes parameter required (hex string)")
    try:
        raw = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        raise RpcError("INVALID_PARAMS", "Invalid hex string")
    original = ida_bytes.get_bytes(ea, len(raw))
    if original is None:
        raise RpcError("READ_FAILED", f"Cannot read {len(raw)} bytes at {_fmt_addr(ea)}")
    orig_hex = _bytes_to_hex(original)
    for i, byte_val in enumerate(raw):
        ida_bytes.patch_byte(ea + i, byte_val)
    _maybe_save_db()
    return {
        "addr": _fmt_addr(ea),
        "size": len(raw),
        "original": orig_hex,
        "patched": _bytes_to_hex(raw),
    }


# Shared globals for exec — persists user variables across calls (shell REPL support)
_exec_globals = {"__builtins__": __builtins__}


def _handle_exec(params):
    if not _fw._config.get("security", {}).get("exec_enabled", False):
        raise RpcError("EXEC_DISABLED",
                        "exec is disabled in config (security.exec_enabled=false)",
                        suggestion="Set security.exec_enabled to true in config.json")
    code = _require_param(params, "code")
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buf), \
             contextlib.redirect_stderr(stderr_buf):
            exec(code, _exec_globals)
    except Exception as e:
        stderr_buf.write(f"{type(e).__name__}: {e}\n")
    saved_to = _save_output(params.get("output"), stdout_buf.getvalue())
    return {
        "stdout": stdout_buf.getvalue(),
        "stderr": stderr_buf.getvalue(),
        "saved_to": saved_to,
    }
