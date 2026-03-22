"""List API — functions, strings, imports, exports, segments, summary."""

import os

from .. import framework as _fw
from ..framework import (
    _fmt_addr, _paginate, _perm_str, STRING_TYPE_UNICODE,
)


def _handle_get_functions(params):
    import idc, idautils, ida_funcs
    filt = params.get("filter")
    funcs = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if filt and filt.lower() not in name.lower():
            continue
        func = ida_funcs.get_func(ea)
        funcs.append({"addr": _fmt_addr(ea), "name": name,
                       "size": func.size() if func else 0})
    return _paginate(funcs, params)


def _handle_get_strings(params):
    import idautils, idc
    filt = params.get("filter")
    enc_filter = params.get("encoding")  # "unicode" or "ascii" or None
    strings = []
    for s in idautils.Strings():
        enc = "utf-16" if s.strtype == STRING_TYPE_UNICODE else "ascii"
        if enc_filter:
            if enc_filter == "unicode" and enc != "utf-16":
                continue
            if enc_filter == "ascii" and enc != "ascii":
                continue
        val = idc.get_strlit_contents(s.ea, s.length, s.strtype)
        if val is None:
            continue
        try:
            decoded = val.decode("utf-8", errors="replace")
        except Exception:
            decoded = val.hex()
        if filt and filt.lower() not in decoded.lower():
            continue
        strings.append({"addr": _fmt_addr(s.ea), "value": decoded,
                         "length": s.length, "encoding": enc})
    return _paginate(strings, params)


def _handle_get_imports(params):
    import ida_nalt
    filt = params.get("filter")
    imports = []
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i)
        def cb(ea, name, ordinal, _mod=mod):
            if name is None:
                name = ""
            if filt and filt.lower() not in name.lower() and filt.lower() not in (_mod or "").lower():
                return True
            imports.append({"addr": _fmt_addr(ea), "name": name,
                            "module": _mod or "", "ordinal": ordinal})
            return True
        ida_nalt.enum_import_names(i, cb)
    return _paginate(imports, params)


def _handle_get_exports(params):
    import idautils
    filt = params.get("filter")
    exports = []
    for idx, ordinal, ea, name in idautils.Entries():
        if name is None:
            name = ""
        if filt and filt.lower() not in name.lower():
            continue
        exports.append({"addr": _fmt_addr(ea), "name": name, "ordinal": ordinal})
    return _paginate(exports, params)


def _handle_get_segments(params):
    import idautils, ida_segment
    segments = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if not seg:
            continue
        segments.append({
            "start_addr": _fmt_addr(seg.start_ea),
            "end_addr": _fmt_addr(seg.end_ea),
            "name": ida_segment.get_segm_name(seg),
            "class": ida_segment.get_segm_class(seg),
            "size": seg.size(),
            "perm": _perm_str(seg.perm),
        })
    return _paginate(segments, params)


# ── Summary helpers ──────────────────────────

def _get_segments_info():
    """Collect segment information (reuses _handle_get_segments with no pagination limit)."""
    return _handle_get_segments({"count": 9999}).get("data", [])


def _get_imports_summary():
    """Get import module counts."""
    import ida_nalt
    import_modules = {}
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i) or ""
        count = [0]
        def cb(ea, name, ordinal, _c=count):
            _c[0] += 1
            return True
        ida_nalt.enum_import_names(i, cb)
        import_modules[mod] = count[0]
    top_imports = sorted(import_modules.items(), key=lambda x: -x[1])[:10]
    total = sum(import_modules.values())
    return top_imports, total


def _get_strings_sample(top_count):
    """Get a sample of strings and total count."""
    import idc, idautils
    sample = []
    for i, s in enumerate(idautils.Strings()):
        if i >= top_count:
            break
        val = idc.get_strlit_contents(s.ea, s.length, s.strtype)
        if val:
            try:
                decoded = val.decode("utf-8", errors="replace")
            except Exception:
                decoded = val.hex()
            sample.append({"addr": _fmt_addr(s.ea), "value": decoded[:100]})
    total = sum(1 for _ in idautils.Strings())
    return sample, total


def _get_function_stats():
    """Get function size distribution and largest functions."""
    import idc, idautils, ida_funcs
    sizes = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func:
            sizes.append((func.start_ea, func.size()))
    sizes.sort(key=lambda x: -x[1])
    largest = []
    for ea, size in sizes[:10]:
        largest.append({
            "addr": _fmt_addr(ea),
            "name": idc.get_func_name(ea) or "",
            "size": size,
        })
    all_sizes = [s for _, s in sizes]
    avg = round(sum(all_sizes) / len(all_sizes)) if all_sizes else 0
    return len(sizes), largest, avg


def _handle_summary(params):
    """Return a comprehensive binary overview in one call."""
    import idautils, ida_kernwin
    func_count, largest_funcs, avg_func_size = _get_function_stats()
    segments = _get_segments_info()
    top_imports, total_imports = _get_imports_summary()
    try:
        top_count = max(1, min(int(params.get("string_count", 20)), 500))
    except (ValueError, TypeError):
        top_count = 20
    strings_sample, total_strings = _get_strings_sample(top_count)
    export_count = sum(1 for _ in idautils.Entries())
    return {
        "binary": os.path.basename(_fw._binary_path),
        "decompiler": _fw._decompiler_available,
        "ida_version": ida_kernwin.get_kernel_version(),
        "func_count": func_count,
        "total_strings": total_strings,
        "total_imports": total_imports,
        "export_count": export_count,
        "segments": segments,
        "top_import_modules": [{"module": m, "count": c} for m, c in top_imports],
        "strings_sample": strings_sample,
        "largest_functions": largest_funcs,
        "avg_func_size": avg_func_size,
    }
