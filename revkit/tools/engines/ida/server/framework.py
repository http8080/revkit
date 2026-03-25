"""Server framework — HTTP server, RPC dispatch, auth, registry, helpers, main."""

import argparse
import atexit
import base64
import contextlib
import io
import json
import logging
import os
import re
import secrets
import sys
from collections import OrderedDict
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from logging.handlers import RotatingFileHandler

from core.config import load_config
from core.registry import (
    acquire_lock as _core_acquire_lock,
    release_lock as _core_release_lock,
    load_registry as _core_load_registry,
    save_registry as _core_save_registry,
    get_registry_path as _core_get_registry_path,
)
from core.utils import file_md5

# Registry path set once in main() via init_registry_paths
_REGISTRY_PATH = None
_LOCK_PATH = None


def _init_registry_globals():
    """Set module-level registry/lock paths from config (called from main)."""
    global _REGISTRY_PATH, _LOCK_PATH
    _REGISTRY_PATH = str(_core_get_registry_path("ida"))
    _LOCK_PATH = _REGISTRY_PATH + ".lock"


def acquire_lock():
    return _core_acquire_lock(_LOCK_PATH)


def release_lock():
    _core_release_lock(_LOCK_PATH)


def load_registry():
    entries = _core_load_registry(_REGISTRY_PATH)
    return {e["id"]: e for e in entries if "id" in e}


def save_registry(registry):
    if isinstance(registry, dict):
        _core_save_registry(_REGISTRY_PATH, list(registry.values()))
    else:
        _core_save_registry(_REGISTRY_PATH, registry)

AUTO_GENERATED_PREFIXES = (
    "sub_", "loc_", "unk_", "off_",
    "byte_", "word_", "dword_", "qword_",
)


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
    except OSError:
        pass


def init_registry_paths(config: dict) -> None:
    """Ensure registry-related directories exist and init globals."""
    _init_registry_globals()
    paths = config.get("paths", {})
    for key in ("idb_dir", "log_dir"):
        p = paths.get(key)
        if p:
            os.makedirs(p, exist_ok=True)
    ida_cfg = config.get("ida", {})
    reg = ida_cfg.get("registry", "")
    if reg:
        reg = os.path.expanduser(reg)
        os.makedirs(os.path.dirname(reg), exist_ok=True)

SERVER_VERSION = "2.0"

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

MAX_BATCH_DECOMPILE = 20
MAX_DISASM_LINES = 500
DEFAULT_DISASM_COUNT = 20
MAX_READ_BYTES = 4096
DEFAULT_FIND_MAX = 50
MAX_FIND_RESULTS = 200
DEFAULT_SEARCH_MAX = 100
MAX_SEARCH_RESULTS = 500
MAX_REQUEST_BODY = 1024 * 1024  # 1 MB
STRING_TYPE_UNICODE = 1

# Segment permissions
SEGPERM_READ = 4
SEGPERM_WRITE = 2
SEGPERM_EXEC = 1

# AUTO_GENERATED_PREFIXES: imported from shared.constants


# ─────────────────────────────────────────────
# RpcError
# ─────────────────────────────────────────────

class RpcError(Exception):
    def __init__(self, code, message, suggestion=None):
        self.code = code
        self.message = message
        self.suggestion = suggestion


# ─────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────

_server = None
_keep_running = True
_db_closed = False
_start_time = None
_auth_token = None
_instance_id = None
_binary_path = None
_config = None
_decompiler_available = False
log = logging.getLogger("ida-headless")


# ─────────────────────────────────────────────
# Decompiler cache (Optimization: avoid repeated decompile)
# ─────────────────────────────────────────────

_decompile_cache = OrderedDict()
_DECOMPILE_CACHE_MAX = 500


def cached_decompile(ea):
    """Decompile function at ea with LRU caching. Returns code string or None."""
    import ida_hexrays, ida_funcs
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    key = func.start_ea
    cached = _decompile_cache.get(key)
    if cached is not None:
        _decompile_cache.move_to_end(key)  # LRU: mark as recently used
        return cached
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            return None
        code = str(cfunc)
    except Exception:
        return None
    _decompile_cache[key] = code
    # Evict least-recently-used entries if cache is full
    while len(_decompile_cache) > _DECOMPILE_CACHE_MAX:
        _decompile_cache.popitem(last=False)
    return code


def invalidate_decompile_cache(ea=None):
    """Invalidate decompiler cache. ea=None clears all."""
    if ea is None:
        _decompile_cache.clear()
    else:
        _decompile_cache.pop(ea, None)


# ─────────────────────────────────────────────
# Function name cache (Optimization: avoid repeated get_func_name)
# ─────────────────────────────────────────────

_func_name_cache = OrderedDict()
_FUNC_NAME_CACHE_MAX = 5000


def cached_func_name(ea):
    """Get function name with LRU caching (max 5000 entries)."""
    cached = _func_name_cache.get(ea)
    if cached is not None:
        _func_name_cache.move_to_end(ea)
        return cached
    import idc
    name = idc.get_func_name(ea) or ""
    _func_name_cache[ea] = name
    while len(_func_name_cache) > _FUNC_NAME_CACHE_MAX:
        _func_name_cache.popitem(last=False)
    return name


def invalidate_func_name_cache(ea=None):
    """Invalidate function name cache."""
    if ea is None:
        _func_name_cache.clear()
    else:
        _func_name_cache.pop(ea, None)


def cached_get_func(ea):
    """Get func_t for ea, with result caching for xref-heavy lookups."""
    import ida_funcs
    return ida_funcs.get_func(ea)


# ─────────────────────────────────────────────
# Registry helpers (server-specific)
# ─────────────────────────────────────────────

@contextlib.contextmanager
def _registry_lock():
    """Context manager for registry lock acquisition."""
    if not acquire_lock():
        log.warning("Could not acquire registry lock")
        yield False
        return
    try:
        yield True
    finally:
        release_lock()


def _update_registry(instance_id, updates):
    with _registry_lock() as ok:
        if not ok:
            return
        r = load_registry()
        if instance_id in r:
            r[instance_id].update(updates)
            save_registry(r)


def _update_state(instance_id, state):
    _update_registry(instance_id, {"state": state})


def _remove_from_registry(instance_id):
    with _registry_lock() as ok:
        if not ok:
            return
        r = load_registry()
        r.pop(instance_id, None)
        save_registry(r)


# ─────────────────────────────────────────────
# Auth token
# ─────────────────────────────────────────────

def _save_auth_token(token_path, instance_id, port, token):
    with _registry_lock() as ok:
        if not ok:
            log.error("Could not acquire lock for auth_token write")
            return
        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        with open(token_path, "a", encoding="utf-8") as f:
            f.write(f"{instance_id}:{port}:{token}\n")


# ─────────────────────────────────────────────
# idb metadata
# ─────────────────────────────────────────────

def _save_idb_metadata(idb_path, binary_path):
    meta = {
        "binary_path": binary_path,
        "binary_md5": file_md5(binary_path),
        "created": time.time(),
    }
    with open(idb_path + ".meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ─────────────────────────────────────────────
# save_db
# ─────────────────────────────────────────────

def save_db():
    """Workaround for ida_loader.save_database() flags=-1 bug. Explicitly use flags=0."""
    import ida_loader
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    ret = ida_loader.save_database(idb, 0)
    if ret:
        log.info(f"Database saved: {idb}")
    else:
        log.error(f"Database save failed: {idb}")
    return ret


# ─────────────────────────────────────────────
# Helpers (addr resolution, pagination, xref)
# ─────────────────────────────────────────────

def _require_decompiler():
    """Raise if decompiler is not available."""
    if not _decompiler_available:
        raise RpcError("DECOMPILER_NOT_LOADED", "Decompiler plugin not available",
                        suggestion="Ensure Hex-Rays decompiler license is installed. Use 'disasm' for assembly output instead.")


def _maybe_save_db():
    """Save database if auto_save is enabled."""
    if _config.get("analysis", {}).get("auto_save", True):
        save_db()


def _require_param(params, key, msg=None):
    """Get a required parameter or raise."""
    val = params.get(key)
    if val is None:
        raise RpcError("INVALID_PARAMS", msg or f"{key} parameter required")
    return val


def _clamp_int(params, key, default, max_val):
    """Get an int parameter clamped to [1, max_val]."""
    return max(1, min(int(params.get(key, default)), max_val))


def _bytes_to_hex(raw):
    """Format bytes as hex string."""
    return " ".join(f"{b:02X}" for b in raw) if raw else ""


def _require_function(ea):
    """Get ida_funcs.get_func(ea) or raise NOT_A_FUNCTION with nearest suggestion."""
    import ida_funcs, idc, idaapi
    func = ida_funcs.get_func(ea)
    if not func:
        suggestion = "Use 'find_func' or 'functions' to find valid function addresses"
        hints = []
        try:
            prev = ida_funcs.get_prev_func(ea)
            if prev != idaapi.BADADDR:
                name = idc.get_func_name(prev) or ""
                hints.append(f"{_fmt_addr(prev)} {name}")
        except Exception:
            pass
        try:
            nxt = ida_funcs.get_next_func(ea)
            if nxt != idaapi.BADADDR:
                name = idc.get_func_name(nxt) or ""
                hints.append(f"{_fmt_addr(nxt)} {name}")
        except Exception:
            pass
        if hints:
            suggestion = f"Nearest functions: {'; '.join(hints)}"
        raise RpcError("NOT_A_FUNCTION", f"No function at {_fmt_addr(ea)}",
                        suggestion=suggestion)
    return func


def _parse_type_str(type_str):
    """Parse a C type declaration string. Returns (tinfo_t, success_bool)."""
    import ida_typeinf
    decl = type_str.rstrip(";") + ";"
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
    return tif, result is not None


def _parse_and_apply_type(ea, type_str):
    """Parse a C type declaration and apply it to an address. Returns tinfo_t."""
    import ida_typeinf
    tif, ok = _parse_type_str(type_str)
    if not ok:
        raise RpcError("PARSE_TYPE_FAILED",
                        f"Cannot parse type declaration: {type_str}",
                        suggestion="Use C syntax, e.g. 'int __fastcall foo(int a, char *b);'")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        raise RpcError("SET_TYPE_FAILED", f"Cannot apply type at {_fmt_addr(ea)}")
    return tif


def _resolve_addr(addr_str):
    """Address string or symbol name → ea_t"""
    import idc
    if addr_str is None:
        raise RpcError("INVALID_PARAMS", "addr parameter required")
    if isinstance(addr_str, int):
        return addr_str
    addr_str = str(addr_str).strip()
    try:
        return int(addr_str, 16)
    except ValueError:
        pass
    ea = idc.get_name_ea_simple(addr_str)
    if ea == idc.BADADDR:
        raise RpcError("INVALID_ADDRESS", f"Cannot resolve: {addr_str}",
                        suggestion=f"Use 'find_func --regex {addr_str}' or 'functions --filter {addr_str}' to search")
    return ea


def _fmt_addr(ea):
    return f"0x{ea:X}"


def _perm_str(perm):
    return (("r" if perm & SEGPERM_READ else "-") +
            ("w" if perm & SEGPERM_WRITE else "-") +
            ("x" if perm & SEGPERM_EXEC else "-"))


def _paginate(all_data, params):
    cfg_out = _config.get("output", {"default_count": 50, "max_count": 500, "encoding": "utf-8"})
    offset = max(0, int(params.get("offset", 0)))
    count = max(0, min(int(params.get("count", cfg_out["default_count"])), cfg_out["max_count"]))
    data = all_data[offset:offset + count]
    saved_to = _save_output(params.get("output"), data, fmt="json") if params.get("output") else None
    return {"total": len(all_data), "offset": offset, "count": len(data),
            "data": data, "saved_to": saved_to}


def _validate_output_path(output_path):
    """Validate output path is under an allowed directory.

    If output_dir is configured and path is outside it, log a warning
    and return None (skip server-side save). The CLI will save locally.
    """
    if not output_path:
        return None
    abspath = os.path.abspath(output_path)
    allowed = _config.get("paths", {}).get("output_dir")
    if allowed:
        allowed_abs = os.path.abspath(os.path.expanduser(allowed))
        if not abspath.startswith(allowed_abs + os.sep) and abspath != allowed_abs:
            log.warning("Output path %s is outside output_dir %s, skipping server-side save",
                            output_path, allowed)
            return None
    return abspath


def _save_output(output_path, content, fmt="text"):
    """Common file save function. fmt: 'text' or 'json'"""
    output_path = _validate_output_path(output_path)
    if not output_path:
        return None
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    encoding = _config.get("output", {}).get("encoding", "utf-8")
    with open(output_path, "w", encoding=encoding) as f:
        if fmt == "json":
            json.dump(content, f, ensure_ascii=False, indent=2)
        else:
            f.write(content)
    return output_path


def _xref_type_str(xtype):
    import ida_xref
    if xtype in (ida_xref.fl_CF, ida_xref.fl_CN):
        return "call"
    if xtype in (ida_xref.fl_JF, ida_xref.fl_JN):
        return "jump"
    if xtype in (ida_xref.dr_R, ida_xref.dr_W, ida_xref.dr_O,
                 ida_xref.dr_I, ida_xref.dr_T, ida_xref.dr_S):
        return "data"
    return "unknown"


_first_segment_ea = None


def _resolve_start_addr(params, key="start"):
    """Resolve optional start address from params, defaulting to first segment (cached)."""
    global _first_segment_ea
    start_str = params.get(key)
    if start_str:
        return _resolve_addr(start_str)
    if _first_segment_ea is None:
        import idautils
        _first_segment_ea = next(iter(idautils.Segments()), 0)
    return _first_segment_ea


# ─────────────────────────────────────────────
# Import handlers (after all helpers are defined to avoid circular import issues)
# ─────────────────────────────────────────────

from .handlers import _dispatch


# ─────────────────────────────────────────────
# HTTP Server + RPC
# ─────────────────────────────────────────────

class RpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        host_header = self.headers.get("Host", "")
        port = _server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if host_header not in allowed:
            self._send_json({"error": {"code": "FORBIDDEN_HOST",
                             "message": "Invalid Host header"}, "id": None})
            return

        import hmac
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth, f"Bearer {_auth_token}"):
            self._send_json({"error": {"code": "AUTH_FAILED",
                             "message": "Invalid or missing auth token"}, "id": None})
            return

        req_id = None
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len == 0:
                raise ValueError("Empty request body")
            if content_len > MAX_REQUEST_BODY:
                raise ValueError(f"Request body too large ({content_len} bytes, max {MAX_REQUEST_BODY})")
            body = json.loads(self.rfile.read(content_len))
            method = body.get("method")
            if not method:
                raise ValueError("Missing 'method' field")
            params = body.get("params", {})
            req_id = body.get("id", 1)

            t0 = time.time()
            trace_id = params.pop("_trace_id", None)
            result = _dispatch(method, params)
            elapsed = round((time.time() - t0) * 1000)
            rpc_data = {"method": method, "elapsed_ms": elapsed}
            if trace_id:
                rpc_data["trace_id"] = trace_id
            record = log.makeRecord(log.name, logging.INFO, "(rpc)", 0,
                                    f"RPC {method} -> OK ({elapsed}ms)", (), None)
            record.extra_data = rpc_data
            log.handle(record)
            self._send_json({"result": result, "id": req_id})
        except RpcError as e:
            m = locals().get('method', '?')
            rpc_data = {"method": m, "error_code": e.code, "error": e.message}
            if locals().get('trace_id'):
                rpc_data["trace_id"] = trace_id
            record = log.makeRecord(log.name, logging.WARNING, "(rpc)", 0,
                                    f"RPC {m} -> {e.code}: {e.message}", (), None)
            record.extra_data = rpc_data
            log.handle(record)
            self._send_json({"error": {"code": e.code, "message": e.message,
                             "suggestion": e.suggestion}, "id": req_id})
        except (json.JSONDecodeError, ValueError) as e:
            self._send_json({"error": {"code": "INVALID_PARAMS",
                             "message": f"Malformed request: {e}"}, "id": req_id})
        except Exception as e:
            log.exception("Unhandled exception in dispatch")
            self._send_json({"error": {"code": "INTERNAL",
                             "message": str(e)}, "id": req_id})

    def _send_json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass  # Suppress BaseHTTPRequestHandler logs (using RotatingFileHandler instead)


# ─────────────────────────────────────────────
# Heartbeat
# ─────────────────────────────────────────────

def _heartbeat_loop(instance_id, interval):
    while _keep_running:
        time.sleep(interval)
        if _keep_running:
            _update_registry(instance_id, {"last_heartbeat": time.time()})


# ─────────────────────────────────────────────
# Decompiler plugin load
# ─────────────────────────────────────────────

def _load_decompiler():
    """Load Hex-Rays decompiler plugin (IDA 9.x unified plugin names)."""
    global _decompiler_available
    import ida_ida, ida_idp, ida_loader, ida_hexrays

    # IDA 9.x: unified plugins — no separate 32/64-bit variants
    _PLFM_MAP = {
        ida_idp.PLFM_386:       "hexx64",
        ida_idp.PLFM_ARM:       "hexarm",
        ida_idp.PLFM_PPC:       "hexppc",
        ida_idp.PLFM_MIPS:      "hexmips",
        ida_idp.PLFM_RISCV:     "hexrv",
        ida_idp.PLFM_NEC_V850X: "hexv850",
        ida_idp.PLFM_ARC:       "hexarc",
    }

    cpu_id = ida_idp.ph.id
    proc_name = ida_ida.inf_get_procname()
    is_64 = ida_ida.inf_is_64bit()
    plugin_name = _PLFM_MAP.get(cpu_id)

    log.info(f"Processor: '{proc_name}', ph.id={cpu_id}, 64bit={is_64}")

    if not plugin_name:
        log.warning(f"No decompiler for: proc='{proc_name}' ph.id={cpu_id}")
        return

    log.info(f"Loading decompiler plugin: {plugin_name}")
    if ida_loader.load_plugin(plugin_name) and ida_hexrays.init_hexrays_plugin():
        log.info(f"Decompiler loaded: {plugin_name}")
        _decompiler_available = True
    else:
        log.error(f"Decompiler load failed: {plugin_name}")


# ─────────────────────────────────────────────
# Main — step-by-step separation
# ─────────────────────────────────────────────

def _setup_logging(log_path, config):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    class _JsonLineFormatter(logging.Formatter):
        def format(self, record):
            from datetime import datetime, timezone
            entry = {
                "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                "level": record.levelname,
                "iid": _instance_id,
                "msg": record.getMessage(),
            }
            if record.exc_info and record.exc_info[1]:
                entry["exception"] = self.formatException(record.exc_info)
            if hasattr(record, "extra_data"):
                entry["data"] = record.extra_data
            return json.dumps(entry, ensure_ascii=False)

    handler = RotatingFileHandler(
        log_path,
        maxBytes=config.get("log", {}).get("max_size_mb", 10) * 1024 * 1024,
        backupCount=config.get("log", {}).get("backup_count", 3),
        encoding="utf-8",
    )
    handler.setFormatter(_JsonLineFormatter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def _log_lifecycle(event, **extra):
    """Log a lifecycle event with structured data to both instance log and stdout."""
    data = {"iid": _instance_id, "event": event, **extra}
    record = log.makeRecord(log.name, logging.INFO, "(server)", 0,
                            f"lifecycle: {event}", (), None)
    record.extra_data = data
    log.handle(record)


def _register_analyzing(instance_id):
    try:
        import psutil
        pid_ct = psutil.Process(os.getpid()).create_time()
    except Exception:
        pid_ct = None
    _update_registry(instance_id, {
        "state": "analyzing",
        "pid": os.getpid(),
        "pid_create_time": pid_ct,
    })


def _open_database(binary_path, idb_path, fresh):
    import idapro
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)
    if os.path.exists(idb_path) and not fresh:
        log.info(f"Reusing existing .i64: {idb_path}")
        result = idapro.open_database(idb_path, True)
    else:
        idb_prefix = os.path.splitext(idb_path)[0]
        log.info(f"New analysis: {binary_path} -> {idb_prefix}")
        result = idapro.open_database(binary_path, True, args=f"-o{idb_prefix}")
        if result == 0:
            _save_idb_metadata(idb_path, binary_path)
    return result


def _start_http_server(config):
    global _server, _auth_token
    host = config.get("server", {}).get("host", "127.0.0.1")
    _server = HTTPServer((host, 0), RpcHandler)
    port = _server.server_address[1]
    log.info(f"HTTP server on {host}:{port}")

    _auth_token = secrets.token_urlsafe(32)
    token_path = config.get("security", {}).get("auth_token_file", os.path.expanduser("~/.revkit/auth_tokens.json"))
    _save_auth_token(token_path, _instance_id, port, _auth_token)
    return port


def main():
    global _start_time, _instance_id, _binary_path, _config, _db_closed

    parser = argparse.ArgumentParser(description="idalib HTTP JSON-RPC server")
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument("--id", required=True, help="Instance ID")
    parser.add_argument("--idb", required=True, help=".i64 path")
    parser.add_argument("--log", required=True, help="Log file path")
    parser.add_argument("--config", required=True, help="config.json path")
    parser.add_argument("--fresh", action="store_true", help="Force fresh analysis")
    args = parser.parse_args()

    _instance_id = args.id
    _binary_path = os.path.abspath(args.binary)
    _start_time = time.time()

    # ── config + logging ──
    _config = load_config(args.config)
    # Merge engine-specific security into global security
    engine_security = _config.get("ida", {}).get("security", {})
    if engine_security:
        _config.setdefault("security", {}).update(engine_security)
    init_registry_paths(_config)
    _setup_logging(args.log, _config)
    _log_lifecycle("instance.start", binary=_binary_path, pid=os.getpid())

    # ── registry: analyzing ──
    _register_analyzing(_instance_id)

    # ── watchdog ──
    open_db_timeout = _config.get("analysis", {}).get("open_db_timeout", 300)
    open_db_done = threading.Event()

    def watchdog():
        if open_db_done.wait(timeout=open_db_timeout):
            return
        log.error(f"open_database timeout ({open_db_timeout}s). Forcing exit.")
        _update_state(_instance_id, "error")
        os._exit(1)

    threading.Thread(target=watchdog, daemon=True).start()

    # ── open database ──
    try:
        result = _open_database(_binary_path, args.idb, args.fresh)
    except TypeError as e:
        log.error(f"open_database failed (IDA 9.1+ required for args parameter): {e}")
        _update_state(_instance_id, "error")
        sys.exit(1)

    open_db_done.set()

    if result != 0:
        _log_lifecycle("instance.error", reason=f"open_database returned {result}")
        _update_state(_instance_id, "error")
        sys.exit(1)

    _log_lifecycle("instance.db_open", idb=args.idb)

    # ── decompiler + initial save ──
    _load_decompiler()
    _log_lifecycle("instance.decompiler", available=_decompiler_available)
    save_db()

    # P6: Log instance metadata
    try:
        import ida_funcs, ida_ida, idautils
        func_count = ida_funcs.get_func_qty()
        proc_name = ida_ida.inf_get_procname()
        is_64 = ida_ida.inf_is_64bit()
        _log_lifecycle("instance.metadata",
                       binary=os.path.basename(_binary_path),
                       binary_md5=file_md5(_binary_path),
                       arch=proc_name,
                       is_64bit=is_64,
                       func_count=func_count,
                       decompiler=_decompiler_available,
                       idb=args.idb)
    except Exception:
        pass

    # ── atexit ──
    import idapro

    def cleanup():
        global _db_closed
        _log_lifecycle("instance.stop")
        try:
            if not _db_closed:
                idapro.close_database(save=True)
                _db_closed = True
        except Exception:
            pass
        try:
            _remove_from_registry(_instance_id)
        except Exception:
            pass
        try:
            remove_auth_token(_config.get("security", {}).get("auth_token_file", os.path.expanduser("~/.revkit/auth_tokens.json")), _instance_id)
        except Exception:
            pass

    atexit.register(cleanup)

    # ── HTTP server + auth + heartbeat ──
    port = _start_http_server(_config)

    hb_interval = _config.get("analysis", {}).get("heartbeat_interval", 30)
    threading.Thread(target=_heartbeat_loop, args=(_instance_id, hb_interval), daemon=True).start()

    # ── registry: ready ──
    _update_registry(_instance_id, {
        "state": "ready",
        "port": port,
        "last_heartbeat": time.time(),
    })

    _log_lifecycle("instance.ready", port=port)
    print(f"\n{'='*50}")
    print(f"  ida_server ready")
    print(f"  URL:   http://{_config.get('server', {}).get('host', '127.0.0.1')}:{port}")
    print(f"  Token: {_auth_token}")
    print(f"  ID:    {_instance_id}")
    print(f"{'='*50}\n", flush=True)

    # ── serve (blocking) ──
    _server.serve_forever()

    # ── post-shutdown cleanup ──
    _log_lifecycle("instance.shutdown", uptime=round(time.time() - _start_time, 1))
    if not _db_closed:
        idapro.close_database(save=True)
        _db_closed = True
    _remove_from_registry(_instance_id)
    remove_auth_token(_config.get("security", {}).get("auth_token_file", os.path.expanduser("~/.revkit/auth_tokens.json")), _instance_id)
