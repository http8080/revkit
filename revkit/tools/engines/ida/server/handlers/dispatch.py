"""Dispatch — ping/status/stop, method registry, and RPC dispatcher."""

import os
import time
import threading

from .. import framework as _fw
from ..framework import RpcError, save_db, SERVER_VERSION

from .listing import (
    _handle_get_functions, _handle_get_strings, _handle_get_imports,
    _handle_get_exports, _handle_get_segments, _handle_summary,
)
from .analysis import (
    _handle_decompile, _handle_decompile_with_xrefs, _handle_decompile_batch,
    _handle_disasm, _handle_get_xrefs_to, _handle_get_xrefs_from,
    _handle_find_func, _handle_get_func_info, _handle_get_imagebase,
    _handle_get_bytes, _handle_find_bytes, _handle_stack_frame,
    _handle_switch_table,
)
from .modification import (
    _handle_rename_batch, _handle_set_name, _handle_set_comment,
    _handle_get_comments, _handle_set_type, _handle_save_db,
    _handle_patch_bytes, _handle_exec,
)
from .types import (
    _handle_list_structs, _handle_get_struct, _handle_create_struct,
    _handle_list_enums, _handle_get_enum, _handle_create_enum,
    _handle_list_types, _handle_get_type,
)
from .graph import (
    _handle_callgraph, _handle_cross_refs, _handle_basic_blocks,
)
from .annotations import (
    _handle_export_annotations, _handle_import_annotations,
)
from .snapshot import (
    _handle_snapshot_save, _handle_snapshot_list, _handle_snapshot_restore,
)
from .advanced import (
    _handle_search_const, _handle_search_code, _handle_decompile_diff,
    _handle_auto_rename, _handle_export_script, _handle_detect_vtables,
    _handle_apply_sig, _handle_list_sigs, _handle_decompile_all,
    _handle_strings_xrefs, _handle_func_similarity, _handle_data_refs,
)


# ── Ping / Status / Stop ────────────────────

def _handle_ping():
    return {"ok": True, "state": "ready"}


def _handle_status():
    import ida_kernwin, ida_loader, ida_funcs
    from core.utils import file_md5
    func_count = ida_funcs.get_func_qty()
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return {
        "state": "ready",
        "binary": os.path.basename(_fw._binary_path),
        "idb_path": idb,
        "decompiler_available": _fw._decompiler_available,
        "func_count": func_count,
        "ida_version": ida_kernwin.get_kernel_version(),
        "server_version": SERVER_VERSION,
        "uptime": round(time.time() - _fw._start_time, 1),
        "binary_md5": file_md5(_fw._binary_path) if os.path.exists(_fw._binary_path) else None,
    }


def _handle_stop():
    _fw._keep_running = False
    save_db()
    threading.Thread(target=_fw._server.shutdown, daemon=True).start()
    return {"ok": True}


def _handle_methods():
    return {
        "methods": [{"name": n, "description": d} for n, d in _METHOD_DESCRIPTIONS]
    }


# ── Method registry ─────────────────────────

_METHODS = {
    "ping": lambda p: _handle_ping(),
    "status": lambda p: _handle_status(),
    "stop": lambda p: _handle_stop(),
    "methods": lambda p: _handle_methods(),
    "get_functions": _handle_get_functions,
    "get_strings": _handle_get_strings,
    "get_imports": _handle_get_imports,
    "get_exports": _handle_get_exports,
    "get_segments": _handle_get_segments,
    "decompile": _handle_decompile,
    "decompile_with_xrefs": _handle_decompile_with_xrefs,
    "decompile_batch": _handle_decompile_batch,
    "summary": _handle_summary,
    "disasm": _handle_disasm,
    "get_xrefs_to": _handle_get_xrefs_to,
    "get_xrefs_from": _handle_get_xrefs_from,
    "find_func": _handle_find_func,
    "get_func_info": _handle_get_func_info,
    "get_imagebase": _handle_get_imagebase,
    "get_bytes": _handle_get_bytes,
    "find_bytes": _handle_find_bytes,
    "set_name": _handle_set_name,
    "set_type": _handle_set_type,
    "set_comment": _handle_set_comment,
    "get_comments": _handle_get_comments,
    "save_db": _handle_save_db,
    "exec": _handle_exec,
    "export_annotations": _handle_export_annotations,
    "import_annotations": _handle_import_annotations,
    "callgraph": _handle_callgraph,
    "patch_bytes": _handle_patch_bytes,
    "search_const": _handle_search_const,
    "list_structs": _handle_list_structs,
    "get_struct": _handle_get_struct,
    "create_struct": _handle_create_struct,
    "snapshot_save": _handle_snapshot_save,
    "snapshot_list": _handle_snapshot_list,
    "snapshot_restore": _handle_snapshot_restore,
    "list_enums": _handle_list_enums,
    "get_enum": _handle_get_enum,
    "create_enum": _handle_create_enum,
    "search_code": _handle_search_code,
    "decompile_diff": _handle_decompile_diff,
    "auto_rename": _handle_auto_rename,
    "export_script": _handle_export_script,
    "detect_vtables": _handle_detect_vtables,
    "apply_sig": _handle_apply_sig,
    "list_sigs": _handle_list_sigs,
    "cross_refs": _handle_cross_refs,
    "decompile_all": _handle_decompile_all,
    "list_types": _handle_list_types,
    "get_type": _handle_get_type,
    "strings_xrefs": _handle_strings_xrefs,
    "func_similarity": _handle_func_similarity,
    "data_refs": _handle_data_refs,
    "basic_blocks": _handle_basic_blocks,
    "stack_frame": _handle_stack_frame,
    "switch_table": _handle_switch_table,
    "rename_batch": _handle_rename_batch,
}

_METHOD_DESCRIPTIONS = [
    ("ping", "Check server liveness"),
    ("status", "Get instance status"),
    ("stop", "Gracefully stop instance"),
    ("methods", "List available APIs"),
    ("get_functions", "List functions"),
    ("get_strings", "List strings"),
    ("get_imports", "List imports"),
    ("get_exports", "List exports"),
    ("get_segments", "List segments"),
    ("decompile", "Decompile a function"),
    ("decompile_with_xrefs", "Decompile with caller/callee info"),
    ("decompile_batch", "Batch decompile multiple functions"),
    ("summary", "Get comprehensive binary overview"),
    ("disasm", "Disassemble instructions"),
    ("get_xrefs_to", "Cross-references to an address"),
    ("get_xrefs_from", "Cross-references from an address"),
    ("find_func", "Search function by name"),
    ("get_func_info", "Get detailed function info"),
    ("get_imagebase", "Get binary base address"),
    ("get_bytes", "Read raw bytes"),
    ("find_bytes", "Search byte pattern"),
    ("set_name", "Rename a symbol"),
    ("set_type", "Set function/variable type"),
    ("set_comment", "Set a comment"),
    ("get_comments", "Get comments"),
    ("save_db", "Save database"),
    ("exec", "Execute Python code"),
    ("export_annotations", "Export names/comments/types as JSON"),
    ("import_annotations", "Import annotations from JSON"),
    ("callgraph", "Build function call graph"),
    ("patch_bytes", "Patch bytes at address"),
    ("search_const", "Search for constant/immediate values"),
    ("list_structs", "List structs and unions"),
    ("get_struct", "Get struct details with members"),
    ("create_struct", "Create a new struct"),
    ("snapshot_save", "Save IDB snapshot"),
    ("snapshot_list", "List snapshots"),
    ("snapshot_restore", "Restore IDB from snapshot"),
    ("list_enums", "List enums"),
    ("get_enum", "Get enum details"),
    ("create_enum", "Create a new enum"),
    ("search_code", "Search within decompiled pseudocode"),
    ("decompile_diff", "Decompile function for diffing"),
    ("auto_rename", "Heuristic auto-rename sub_ functions"),
    ("export_script", "Generate IDAPython script from analysis"),
    ("detect_vtables", "Detect virtual function tables"),
    ("apply_sig", "Apply FLIRT signature"),
    ("list_sigs", "List available FLIRT signatures"),
    ("cross_refs", "Multi-level xref chain tracing"),
    ("decompile_all", "Decompile all functions to file"),
    ("list_types", "List local types (typedef, funcptr, etc.)"),
    ("get_type", "Get detailed type info"),
    ("strings_xrefs", "Strings with referencing functions"),
    ("func_similarity", "Compare two functions by similarity"),
    ("data_refs", "Data segment reference analysis"),
    ("basic_blocks", "Basic blocks and CFG for a function"),
    ("stack_frame", "Get stack frame layout with local variables"),
    ("switch_table", "Analyze switch/jump tables in a function"),
    ("rename_batch", "Batch rename from list of addr/name pairs"),
]


# Global lock for IDA API calls — IDA database is NOT thread-safe.
# ThreadingHTTPServer creates a thread per request, so concurrent
# handler calls could corrupt the database without serialization.
_ida_api_lock = threading.Lock()


def _dispatch(method, params):
    handler = _METHODS.get(method)
    if not handler:
        raise RpcError("UNKNOWN_METHOD", f"Unknown method: {method}",
                        suggestion="Call 'methods' to list available APIs")
    with _ida_api_lock:
        return handler(params)
