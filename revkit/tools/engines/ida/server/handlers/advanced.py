"""Advanced API — search, auto-rename, export script, vtables, sigs,
decompile-all, strings-xrefs, func-similarity, data-refs."""

import os
import re

from ..framework import (
    RpcError, _fmt_addr, _require_param, _clamp_int,
    _require_function, _require_decompiler, _resolve_addr,
    _save_output, _xref_type_str, _maybe_save_db,
    AUTO_GENERATED_PREFIXES,
    DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS,
    SEGPERM_EXEC, STRING_TYPE_UNICODE,
)


# ── Search by constant/immediate ────────────

def _handle_search_const(params):
    """Search for immediate/constant values in instructions."""
    import idautils, idc, ida_ua, ida_funcs
    value = params.get("value")
    if value is None:
        raise RpcError("INVALID_PARAMS", "value parameter required")
    target = int(str(value), 0)
    max_results = _clamp_int(params, "max_results", DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS)
    results = []
    for seg_ea in idautils.Segments():
        ea = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        while ea < end and len(results) < max_results:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length > 0:
                for op in insn.ops:
                    if op.type == 0:
                        break
                    if op.type == ida_ua.o_imm and op.value == target:
                        func = ida_funcs.get_func(ea)
                        results.append({
                            "addr": _fmt_addr(ea),
                            "func": (idc.get_func_name(ea) or "") if func else "",
                            "disasm": idc.generate_disasm_line(ea, 0),
                        })
                        break
                ea += length
            else:
                ea += 1
    saved_to = _save_output(params.get("output"), results, fmt="json")
    return {
        "value": _fmt_addr(target), "total": len(results), "results": results, "saved_to": saved_to,
        "hint": "value is the searched constant (hex formatted). total = match count.",
    }


# ── Pseudocode search ───────────────────────

def _handle_search_code(params):
    """Search for a string within decompiled pseudocode."""
    _require_decompiler()
    import ida_hexrays, idc, idautils, ida_funcs
    query = _require_param(params, "query")
    case_sensitive = params.get("case_sensitive", False)
    max_results = _clamp_int(params, "max_results", 20, 100)
    max_funcs = _clamp_int(params, "max_funcs", 500, 2000)

    if not case_sensitive:
        query_lower = query.lower()

    results = []
    func_count = 0
    for ea in idautils.Functions():
        if func_count >= max_funcs or len(results) >= max_results:
            break
        func_count += 1
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                continue
            code = str(cfunc)
        except Exception:
            continue
        if case_sensitive:
            match = query in code
        else:
            match = query_lower in code.lower()
        if match:
            name = idc.get_func_name(func.start_ea) or ""
            matching_lines = []
            for i, line in enumerate(code.split("\n")):
                if case_sensitive:
                    if query in line:
                        matching_lines.append({"line_num": i + 1, "text": line.strip()})
                else:
                    if query_lower in line.lower():
                        matching_lines.append({"line_num": i + 1, "text": line.strip()})
            results.append({
                "addr": _fmt_addr(func.start_ea),
                "name": name,
                "matches": matching_lines[:5],
            })
    saved_to = _save_output(params.get("output"), results, fmt="json")
    return {
        "query": query,
        "total": len(results),
        "functions_scanned": func_count,
        "results": results,
        "saved_to": saved_to,
        "hint": "total = matching functions count, functions_scanned = total functions examined (not results).",
    }


# ── Decompile diff ──────────────────────────

def _handle_decompile_diff(params):
    """Decompile a function and return code for diffing."""
    _require_decompiler()
    import ida_hexrays, idc
    ea = _resolve_addr(params.get("addr"))
    func = _require_function(ea)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        code = str(cfunc) if cfunc else ""
    except Exception as e:
        code = f"// Decompile failed: {e}"
    name = idc.get_func_name(func.start_ea) or ""
    size = func.end_ea - func.start_ea
    return {
        "addr": _fmt_addr(func.start_ea), "name": name, "size": size, "code": code,
        "hint": "Single function decompile for diff preparation. Not a two-function comparison.",
    }


# ── Auto-rename (heuristic) ─────────────────

def _suggest_name_by_string(ea):
    """Strategy 1: Suggest function name based on string references."""
    import idc, idautils
    for item_ea in idautils.FuncItems(ea):
        for xref in idautils.DataRefsFrom(item_ea):
            s = idc.get_strlit_contents(xref)
            if s and len(s) >= 4:
                try:
                    s = s.decode("utf-8", errors="ignore")
                except Exception:
                    s = str(s)
                clean = ""
                for ch in s[:40]:
                    if ch.isalnum() or ch == '_':
                        clean += ch
                    elif ch in (' ', '-', '.', '/'):
                        clean += '_'
                clean = clean.strip('_')
                if clean and len(clean) >= 3 and not clean[0].isdigit():
                    return f"fn_{clean}"
    return None


def _suggest_name_by_api(ea):
    """Strategy 2: Suggest function name based on API calls."""
    import idc, idautils, ida_xref
    _skip_funcs = ("__security_check_cookie", "memset_0", "_guard_dispatch_icall")
    api_calls = []
    for item_ea in idautils.FuncItems(ea):
        for xref in idautils.XrefsFrom(item_ea):
            target_name = idc.get_func_name(xref.to)
            if target_name and not target_name.startswith("sub_") and not target_name.startswith("nullsub_"):
                if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                    api_calls.append(target_name)
    for api in api_calls:
        if api in _skip_funcs:
            continue
        clean = api.split("@")[0].lstrip("?_")
        if clean and len(clean) >= 3:
            return f"calls_{clean[:30]}"
    return None


def _handle_auto_rename(params):
    """Heuristic-based automatic function renaming."""
    import idc, idautils, ida_funcs
    max_funcs = _clamp_int(params, "max_funcs", 200, 1000)
    dry_run = params.get("dry_run", True)

    renames = []
    count = 0
    for ea in idautils.Functions():
        if count >= max_funcs:
            break
        name = idc.get_func_name(ea)
        if not name or not name.startswith("sub_"):
            continue
        count += 1
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        suggested = _suggest_name_by_string(ea) or _suggest_name_by_api(ea)
        if suggested:
            if idc.get_name_ea_simple(suggested) != idc.BADADDR:
                suggested = f"{suggested}_{_fmt_addr(ea).replace('0x', '')}"
            renames.append({
                "addr": _fmt_addr(ea),
                "old_name": name,
                "new_name": suggested,
            })
            if not dry_run:
                idc.set_name(ea, suggested, idc.SN_NOWARN | idc.SN_NOCHECK)

    if not dry_run and renames:
        _maybe_save_db()
    result = {"total": len(renames), "dry_run": dry_run, "renames": renames}
    if count == 0:
        result["hint"] = "No sub_ prefixed functions found. Fully symbolicated binaries have no rename targets."
    elif len(renames) == 0 and count > 0:
        result["hint"] = f"Scanned {count} sub_ functions but no heuristic matched. Try increasing max_funcs or check binary has string/API refs."
    else:
        result["hint"] = f"Only sub_ prefixed functions are candidates. Scanned {count}, suggested {len(renames)}."
    return result


# ── Generate IDAPython script ────────────────

def _collect_func_metadata():
    """Single-pass collection of renames, comments, and types from all functions."""
    import idc, idautils, ida_funcs
    rename_lines, comment_lines, type_lines = [], [], []
    for ea in idautils.Functions():
        addr = _fmt_addr(ea)
        name = idc.get_func_name(ea)
        if name and not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            rename_lines.append(f'idc.set_name({addr}, "{name}", idc.SN_NOWARN)')
        cmt = idc.get_cmt(ea, False)
        if cmt:
            comment_lines.append(f'idc.set_cmt({addr}, {repr(cmt)}, False)')
        rcmt = idc.get_cmt(ea, True)
        if rcmt:
            comment_lines.append(f'idc.set_cmt({addr}, {repr(rcmt)}, True)')
        fcmt = idc.get_func_cmt(ea, False)
        if fcmt:
            comment_lines.append(f'idc.set_func_cmt({addr}, {repr(fcmt)}, False)')
        type_str = idc.get_type(ea)
        if type_str:
            type_lines.append(f'idc.SetType({addr}, "{type_str}")')
    for item in idautils.Names():
        ea, name = item[0], item[1]
        if not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            if not ida_funcs.get_func(ea):
                rename_lines.append(f'idc.set_name({_fmt_addr(ea)}, "{name}", idc.SN_NOWARN)')
    return rename_lines, comment_lines, type_lines


def _handle_export_script(params):
    """Generate reproducible IDAPython script from analysis."""
    rename_lines, comment_lines, type_lines = _collect_func_metadata()
    lines = [
        "#!/usr/bin/env python3",
        '"""Auto-generated IDAPython script from ida-cli analysis."""',
        "import idc",
        "import ida_typeinf",
        "",
    ]
    lines += rename_lines + [""] + comment_lines + [""] + type_lines
    rc, cc, tc = len(rename_lines), len(comment_lines), len(type_lines)
    lines += [
        "",
        f'renames = {rc}',
        f'comments = {cc}',
        f'types = {tc}',
        f'print(f"Applied {{renames}} renames, {{comments}} comments, {{types}} types")',
    ]
    script = "\n".join(lines)
    saved_to = _save_output(params.get("output"), script)
    resp = {
        "renames": rc, "comments": cc, "types": tc, "saved_to": saved_to,
        "hint": "renames/comments/types are counts (int), not lists. Actual script content is in saved_to file or 'script' key.",
    }
    if not saved_to:
        resp["script"] = script
    return resp


# ── VTable detection ────────────────────────

def _handle_detect_vtables(params):
    """Detect virtual function tables in data segments."""
    import idc, idautils, ida_funcs, ida_bytes, ida_segment
    max_results = _clamp_int(params, "max_results", 50, 200)
    try:
        min_entries = int(params.get("min_entries", 3))
    except (ValueError, TypeError):
        min_entries = 3
    ptr_size = 8 if idc.get_inf_attr(idc.INF_LFLAGS) & 1 else 4

    vtables = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        perm = seg.perm
        if perm & SEGPERM_EXEC:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and len(vtables) < max_results:
            if ptr_size == 8:
                val = ida_bytes.get_qword(ea)
            else:
                val = ida_bytes.get_dword(ea)
            if val and ida_funcs.get_func(val):
                entries = []
                check_ea = ea
                while check_ea < seg.end_ea:
                    if ptr_size == 8:
                        ptr_val = ida_bytes.get_qword(check_ea)
                    else:
                        ptr_val = ida_bytes.get_dword(check_ea)
                    if ptr_val and ida_funcs.get_func(ptr_val):
                        entries.append({
                            "offset": check_ea - ea,
                            "addr": _fmt_addr(ptr_val),
                            "name": idc.get_func_name(ptr_val) or "",
                        })
                        check_ea += ptr_size
                    else:
                        break
                if len(entries) >= min_entries:
                    vtables.append({
                        "addr": _fmt_addr(ea),
                        "entries": len(entries),
                        "functions": entries[:20],
                    })
                    ea = check_ea
                    continue
            ea += ptr_size
    return {
        "total": len(vtables), "ptr_size": ptr_size, "vtables": vtables,
        "hint": "total = vtable count, not entry count. Each vtable has entries (int) and functions (list).",
    }


# ── FLIRT signatures ────────────────────────

def _handle_apply_sig(params):
    """Apply FLIRT signature file."""
    import ida_funcs, ida_diskio
    sig_name = _require_param(params, "name", "name parameter required (signature name without .sig)")
    # Validate signature file exists before calling IDA API
    # (plan_to_apply_idasgn silently returns 0 for nonexistent sigs)
    sig_dir = ida_diskio.idadir("sig")
    sig_path = os.path.join(sig_dir, sig_name + ".sig")
    if not os.path.isfile(sig_path):
        # Try with subdirectory (e.g. "arm/android_arm" -> sig/arm/android_arm.sig)
        parts = sig_name.replace("\\", "/").split("/")
        if len(parts) == 2:
            sig_path = os.path.join(sig_dir, parts[0], parts[1] + ".sig")
        if not os.path.isfile(sig_path):
            raise RpcError("SIG_NOT_FOUND", f"Signature file not found: {sig_name}")
    try:
        result = ida_funcs.plan_to_apply_idasgn(sig_name)
        _maybe_save_db()
        return {"ok": True, "signature": sig_name, "result": result}
    except Exception as e:
        raise RpcError("APPLY_SIG_FAILED", f"Cannot apply signature: {e}")


def _handle_list_sigs(params):
    """List available FLIRT signature files."""
    import ida_diskio
    sig_dir = ida_diskio.idadir("sig")
    sigs = []
    if os.path.isdir(sig_dir):
        for f in sorted(os.listdir(sig_dir)):
            if f.endswith(".sig"):
                fpath = os.path.join(sig_dir, f)
                sigs.append({
                    "name": f[:-4],
                    "filename": f,
                    "size": os.path.getsize(fpath),
                })
        for sub in os.listdir(sig_dir):
            sub_path = os.path.join(sig_dir, sub)
            if os.path.isdir(sub_path):
                for f in sorted(os.listdir(sub_path)):
                    if f.endswith(".sig"):
                        fpath = os.path.join(sub_path, f)
                        sigs.append({
                            "name": f"{sub}/{f[:-4]}",
                            "filename": f,
                            "size": os.path.getsize(fpath),
                        })
    return {"total": len(sigs), "sig_dir": sig_dir, "signatures": sigs}


# ── Decompile All ───────────────────────────

def _handle_decompile_all(params):
    """Decompile all (or filtered) functions and save to a .c file."""
    _require_decompiler()
    import ida_hexrays, idc, idautils, ida_funcs
    filt = params.get("filter", "")
    skip_thunks = params.get("skip_thunks", True)
    skip_libs = params.get("skip_libs", True)
    output_path = _require_param(params, "output")

    results = []
    success = 0
    failed = 0
    skipped = 0
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        name = idc.get_func_name(ea) or ""
        if filt and filt.lower() not in name.lower():
            continue
        if skip_thunks and (func.flags & ida_funcs.FUNC_THUNK):
            skipped += 1
            continue
        if skip_libs and (func.flags & ida_funcs.FUNC_LIB):
            skipped += 1
            continue
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                results.append(f"// \u2500\u2500 {name} ({_fmt_addr(ea)}) \u2500\u2500\n{str(cfunc)}")
                success += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    split = params.get("split", False)
    actual_saved = None
    text = "\n\n".join(results)
    if split:
        os.makedirs(output_path, exist_ok=True)
        actual_saved = output_path
        for entry in results:
            match = re.match(r'// \u2500\u2500 (\S+)', entry)
            fname = match.group(1) if match else f"func_{results.index(entry)}"
            safe_name = re.sub(r'[^\w\-.]', '_', fname)
            max_name = 200 - len(output_path)
            if max_name < 40:
                max_name = 40
            if len(safe_name) > max_name:
                safe_name = safe_name[:max_name]
            fpath = os.path.join(output_path, f"{safe_name}.c")
            counter = 1
            while os.path.exists(fpath):
                fpath = os.path.join(output_path, f"{safe_name}_{counter}.c")
                counter += 1
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(entry)
    else:
        actual_saved = _save_output(output_path, text)
    resp = {
        "total": success + failed + skipped, "success": success,
        "failed": failed, "skipped": skipped,
        "saved_to": actual_saved,
        "split": split,
        "hint": "All values are counts. Decompiled code is saved to saved_to path. output param is required.",
    }
    if not actual_saved:
        resp["code"] = text
    return resp


# ── Strings with Xrefs ─────────────────────

def _handle_strings_xrefs(params):
    """Get strings with their referencing functions in one call."""
    import idautils, idc, ida_funcs
    filt = params.get("filter", "")
    max_results = _clamp_int(params, "max_results", DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS)
    try:
        min_refs = max(0, int(params.get("min_refs", 0)))
    except (ValueError, TypeError):
        min_refs = 0

    results = []
    for s in idautils.Strings():
        if len(results) >= max_results:
            break
        val = idc.get_strlit_contents(s.ea, s.length, s.strtype)
        if val is None:
            continue
        try:
            decoded = val.decode("utf-8", errors="replace")
        except Exception:
            decoded = val.hex()
        if filt and filt.lower() not in decoded.lower():
            continue
        refs = []
        for xref in idautils.XrefsTo(s.ea):
            func = ida_funcs.get_func(xref.frm)
            refs.append({
                "addr": _fmt_addr(xref.frm),
                "func_addr": _fmt_addr(func.start_ea) if func else None,
                "func_name": idc.get_func_name(func.start_ea) if func else "",
                "type": _xref_type_str(xref.type),
            })
        if min_refs and len(refs) < min_refs:
            continue
        enc = "utf-16" if s.strtype == STRING_TYPE_UNICODE else "ascii"
        results.append({
            "addr": _fmt_addr(s.ea), "value": decoded,
            "length": s.length, "encoding": enc,
            "ref_count": len(refs), "refs": refs,
        })
    return {
        "total": len(results), "results": results,
        "hint": "Each result has ref_count (int) and refs (list). total is string count, not ref count.",
    }


# ── Function Similarity ─────────────────────

def _handle_func_similarity(params):
    """Compare two functions by size, basic blocks, and call graph."""
    import ida_funcs, ida_gdl, idc, idautils
    ea_a = _resolve_addr(_require_param(params, "addr_a"))
    ea_b = _resolve_addr(_require_param(params, "addr_b"))
    func_a = _require_function(ea_a)
    func_b = _require_function(ea_b)

    def _func_metrics(func):
        block_count = sum(1 for _ in ida_gdl.FlowChart(func))
        callees = set()
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(item_ea):
                target = ida_funcs.get_func(xref.to)
                if target and target.start_ea != func.start_ea:
                    callees.add(idc.get_func_name(target.start_ea)
                                or _fmt_addr(target.start_ea))
        return {
            "addr": _fmt_addr(func.start_ea),
            "name": idc.get_func_name(func.start_ea) or "",
            "size": func.size(),
            "block_count": block_count,
            "callee_count": len(callees),
            "callees": sorted(callees),
        }

    m_a = _func_metrics(func_a)
    m_b = _func_metrics(func_b)
    max_size = max(m_a["size"], m_b["size"])
    max_blocks = max(m_a["block_count"], m_b["block_count"])
    size_ratio = min(m_a["size"], m_b["size"]) / max_size if max_size else 1.0
    block_ratio = min(m_a["block_count"], m_b["block_count"]) / max_blocks if max_blocks else 1.0
    common_callees = set(m_a["callees"]) & set(m_b["callees"])
    all_callees = set(m_a["callees"]) | set(m_b["callees"])
    callee_jaccard = len(common_callees) / len(all_callees) if all_callees else 1.0
    overall = round((size_ratio + block_ratio + callee_jaccard) / 3, 4)
    return {
        "func_a": m_a, "func_b": m_b,
        "similarity": {
            "size_ratio": round(size_ratio, 4),
            "block_ratio": round(block_ratio, 4),
            "callee_jaccard": round(callee_jaccard, 4),
            "overall": overall,
        },
        "common_callees": sorted(common_callees),
        "hint": "overall is under similarity (similarity.overall). Scores: size_ratio, block_ratio, callee_jaccard averaged.",
    }


# ── Data Refs ───────────────────────────────

def _handle_data_refs(params):
    """Analyze data references: named globals in data segments with xrefs."""
    import idautils, idc, ida_segment, ida_funcs
    filt = params.get("filter", "")
    max_results = _clamp_int(params, "max_results", DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS)
    segment_filter = params.get("segment", "")

    results = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg) or ""
        if segment_filter:
            if segment_filter.lower() not in seg_name.lower():
                continue
        elif seg.perm & SEGPERM_EXEC:
            continue

        ea = seg.start_ea
        while ea < seg.end_ea and len(results) < max_results:
            name = idc.get_name(ea)
            if not name or name.startswith(("unk_", "byte_", "word_", "dword_", "qword_")):
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idc.BADADDR:
                    break
                continue
            if filt and filt.lower() not in name.lower():
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idc.BADADDR:
                    break
                continue
            refs = []
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                refs.append({
                    "addr": _fmt_addr(xref.frm),
                    "func": idc.get_func_name(func.start_ea) if func else "",
                    "type": _xref_type_str(xref.type),
                })
            results.append({
                "addr": _fmt_addr(ea), "name": name,
                "segment": seg_name, "size": idc.get_item_size(ea),
                "ref_count": len(refs), "refs": refs,
            })
            ea = idc.next_head(ea, seg.end_ea)
            if ea == idc.BADADDR:
                break

    return {
        "total": len(results), "results": results,
        "hint": "Each result has ref_count (int) and refs (list). total is data item count, not ref count.",
    }
