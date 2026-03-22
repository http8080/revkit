"""Annotations API — export/import names, comments, types."""

import os

from ..framework import (
    _fmt_addr, _resolve_addr, _save_output, _require_param,
    _parse_type_str, _maybe_save_db, AUTO_GENERATED_PREFIXES,
)
from .. import framework as _fw


def _collect_function_annotations(annotations):
    """Collect names, comments, and types from functions."""
    import idc, idautils
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if name and not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            annotations["names"].append({"addr": _fmt_addr(ea), "name": name})
        cmt = idc.get_cmt(ea, False)
        rcmt = idc.get_cmt(ea, True)
        fcmt = idc.get_func_cmt(ea, False)
        if cmt or rcmt or fcmt:
            entry = {"addr": _fmt_addr(ea)}
            if cmt: entry["comment"] = cmt
            if rcmt: entry["repeatable"] = rcmt
            if fcmt: entry["func_comment"] = fcmt
            annotations["comments"].append(entry)
        type_str = idc.get_type(ea)
        if type_str:
            annotations["types"].append({"addr": _fmt_addr(ea), "type": type_str})


def _collect_global_names(annotations):
    """Collect non-function names (globals, data labels)."""
    import idautils, ida_funcs
    for item in idautils.Names():
        ea = item[0]
        name = item[1]
        if not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            func = ida_funcs.get_func(ea)
            if not func:
                annotations["names"].append({"addr": _fmt_addr(ea), "name": name})


def _handle_export_annotations(params):
    """Export all user-applied names, comments, and types."""
    import idc, ida_nalt
    annotations = {
        "binary": os.path.basename(idc.get_input_file_path()),
        "imagebase": _fmt_addr(ida_nalt.get_imagebase()),
        "names": [],
        "comments": [],
        "types": [],
    }
    _collect_function_annotations(annotations)
    _collect_global_names(annotations)
    saved_to = _save_output(params.get("output"), annotations, fmt="json")
    annotations["saved_to"] = saved_to
    return annotations


def _import_names(data, stats):
    """Import name annotations."""
    import idc
    for entry in data.get("names", []):
        try:
            ea = _resolve_addr(entry["addr"])
            idc.set_name(ea, entry["name"], idc.SN_NOWARN | idc.SN_NOCHECK)
            stats["names"] += 1
        except Exception:
            stats["errors"] += 1


def _import_comments(data, stats):
    """Import comment annotations."""
    import idc
    for entry in data.get("comments", []):
        try:
            ea = _resolve_addr(entry["addr"])
            if "comment" in entry:
                idc.set_cmt(ea, entry["comment"], False)
            if "repeatable" in entry:
                idc.set_cmt(ea, entry["repeatable"], True)
            if "func_comment" in entry:
                idc.set_func_cmt(ea, entry["func_comment"], False)
            stats["comments"] += 1
        except Exception:
            stats["errors"] += 1


def _import_types(data, stats):
    """Import type annotations.

    idc.get_type() returns nameless prototypes like 'void __cdecl()'.
    parse_decl() often fails on these, so we inject a dummy name '_f'
    between the calling convention and the '(' to make it parseable.
    """
    import re
    import ida_typeinf
    for entry in data.get("types", []):
        try:
            ea = _resolve_addr(entry["addr"])
            type_str = entry["type"]
            tif, ok = _parse_type_str(type_str)
            if not ok:
                # Insert dummy name before '(' to help parse_decl:
                #   "void __cdecl()" → "void __cdecl _f()"
                #   "void __cdecl __noreturn()" → "void __cdecl __noreturn _f()"
                patched = re.sub(
                    r'(\b(?:__cdecl|__stdcall|__fastcall|__thiscall|__usercall|__userpurge)'
                    r'(?:\s+__noreturn)?)\s*\(',
                    r'\1 _f(', type_str, count=1)
                if patched == type_str:
                    # No calling convention — nameless like "void(...)" or "int(HWND,...)"
                    # Insert _f right before the first '(' that follows a type
                    patched = re.sub(r'^([^(]+?)\s*\(', r'\1 _f(', type_str, count=1)
                if patched != type_str:
                    tif, ok = _parse_type_str(patched)
            if ok:
                ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
                stats["types"] += 1
            else:
                stats["errors"] += 1
        except Exception:
            stats["errors"] += 1


def _handle_import_annotations(params):
    """Import annotations from JSON."""
    data = _require_param(params, "data", "data parameter required (JSON annotations)")
    stats = {"names": 0, "comments": 0, "types": 0, "errors": 0}
    _import_names(data, stats)
    _import_comments(data, stats)
    _import_types(data, stats)
    _maybe_save_db()
    return stats
