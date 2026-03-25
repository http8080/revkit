"""Analysis API — decompile, disasm, xrefs, func info, bytes."""

import re

from .. import framework as _fw
from ..framework import (
    RpcError, _fmt_addr, _require_param, _clamp_int, _bytes_to_hex,
    _require_function, _require_decompiler, _resolve_addr, _save_output,
    _xref_type_str, _resolve_start_addr,
    cached_decompile, cached_func_name,
    MAX_BATCH_DECOMPILE, MAX_DISASM_LINES, DEFAULT_DISASM_COUNT,
    MAX_READ_BYTES, DEFAULT_FIND_MAX, MAX_FIND_RESULTS,
    DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS,
)


def _decompile_func(ea):
    """Decompile function at ea. Returns (func, code, name). Uses cache."""
    import ida_hexrays
    _require_decompiler()
    func = _require_function(ea)
    # Try cache first
    code = cached_decompile(func.start_ea)
    if code is not None:
        name = cached_func_name(func.start_ea)
        return func, code, name
    # Cache miss — decompile directly (for better error reporting)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RpcError("DECOMPILE_FAILED", f"Decompile returned None at {_fmt_addr(ea)}")
        code = str(cfunc)
    except ida_hexrays.DecompilationFailure as e:
        raise RpcError("DECOMPILE_FAILED", str(e))
    name = cached_func_name(func.start_ea)
    return func, code, name


def _handle_decompile(params):
    ea = _resolve_addr(params.get("addr"))
    func, code, name = _decompile_func(ea)
    if params.get("raw"):
        code = re.sub(r'/\*\s*0x[0-9A-Fa-f]+\s*\*/', '', code)
        code = re.sub(r'\n{3,}', '\n\n', code)
    saved_to = _save_output(params.get("output"), code)
    return {"addr": _fmt_addr(func.start_ea), "name": name,
            "code": code, "saved_to": saved_to}


def _handle_decompile_with_xrefs(params):
    """Decompile + xrefs_to in a single call."""
    import idautils, ida_funcs
    ea = _resolve_addr(params.get("addr"))
    func, code, name = _decompile_func(ea)
    callers = []
    for xref in idautils.XrefsTo(func.start_ea):
        callers.append({
            "from_addr": _fmt_addr(xref.frm),
            "from_name": cached_func_name(xref.frm),
            "type": _xref_type_str(xref.type),
        })
    callees = []
    seen = set()
    for ea_item in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(ea_item):
            target_func = ida_funcs.get_func(xref.to)
            if target_func and target_func.start_ea != func.start_ea:
                if target_func.start_ea not in seen:
                    seen.add(target_func.start_ea)
                    callees.append({
                        "to_addr": _fmt_addr(target_func.start_ea),
                        "to_name": cached_func_name(target_func.start_ea),
                        "type": _xref_type_str(xref.type),
                    })
    output = f"// {name} @ {_fmt_addr(func.start_ea)}\n{code}"
    if callers:
        output += f"\n\n// --- Callers ({len(callers)}) ---"
        for c in callers:
            output += f"\n//   {c['from_addr']}  {c['from_name']}  [{c['type']}]"
    if callees:
        output += f"\n\n// --- Callees ({len(callees)}) ---"
        for c in callees:
            output += f"\n//   {c['to_addr']}  {c['to_name']}  [{c['type']}]"
    saved_to = _save_output(params.get("output"), output)
    return {"addr": _fmt_addr(func.start_ea), "name": name,
            "code": code, "callers": callers, "callees": callees,
            "saved_to": saved_to}


def _handle_decompile_batch(params):
    _require_decompiler()
    import ida_funcs
    addrs = params.get("addrs", [])
    if len(addrs) > MAX_BATCH_DECOMPILE:
        raise RpcError("INVALID_PARAMS", f"Maximum {MAX_BATCH_DECOMPILE} addresses per batch")
    results = []
    success = 0
    for addr_str in addrs:
        try:
            ea = _resolve_addr(addr_str)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": _fmt_addr(ea), "name": "", "error": "NOT_A_FUNCTION"})
                continue
            code = cached_decompile(func.start_ea)
            if not code:
                results.append({"addr": _fmt_addr(func.start_ea),
                                "name": cached_func_name(func.start_ea),
                                "error": "DECOMPILE_FAILED"})
                continue
            results.append({"addr": _fmt_addr(func.start_ea),
                            "name": cached_func_name(func.start_ea),
                            "code": code})
            success += 1
        except RpcError:
            results.append({"addr": addr_str, "name": "", "error": "INVALID_ADDRESS"})
        except Exception as e:
            results.append({"addr": addr_str, "name": "", "error": str(e)})
    output_path = params.get("output")
    if output_path:
        text = "\n\n".join(
            f"// \u2500\u2500 {r['name']} ({r['addr']}) \u2500\u2500\n{r['code']}"
            for r in results if "code" in r
        )
        saved_to = _save_output(output_path, text)
    else:
        saved_to = None
    return {"total": len(addrs), "success": success,
            "failed": len(addrs) - success, "functions": results,
            "saved_to": saved_to}


def _handle_disasm(params):
    import idc, ida_bytes
    ea = _resolve_addr(params.get("addr"))
    count = _clamp_int(params, "count", DEFAULT_DISASM_COUNT, MAX_DISASM_LINES)
    lines = []
    cur = ea
    for _ in range(count):
        insn = idc.generate_disasm_line(cur, 0)
        if insn is None:
            break
        size = idc.get_item_size(cur) or 1
        raw = ida_bytes.get_bytes(cur, size)
        hex_str = _bytes_to_hex(raw) if raw else ""
        lines.append({"addr": _fmt_addr(cur), "bytes": hex_str, "insn": insn})
        cur += size
    text = "\n".join(f"{ln['addr']}  {ln['bytes']:<24}  {ln['insn']}" for ln in lines)
    saved_to = _save_output(params.get("output"), text)
    return {"addr": _fmt_addr(ea), "count": len(lines),
            "lines": lines, "saved_to": saved_to}


def _handle_get_xrefs_to(params):
    import idautils
    ea = _resolve_addr(params.get("addr"))
    refs = []
    for xref in idautils.XrefsTo(ea):
        refs.append({
            "from_addr": _fmt_addr(xref.frm),
            "from_name": cached_func_name(xref.frm),
            "type": _xref_type_str(xref.type),
        })
    return {"addr": _fmt_addr(ea), "total": len(refs), "refs": refs}


def _handle_get_xrefs_from(params):
    import idautils
    ea = _resolve_addr(params.get("addr"))
    refs = []
    for xref in idautils.XrefsFrom(ea):
        refs.append({
            "to_addr": _fmt_addr(xref.to),
            "to_name": cached_func_name(xref.to),
            "type": _xref_type_str(xref.type),
        })
    return {"addr": _fmt_addr(ea), "total": len(refs), "refs": refs}


def _handle_find_func(params):
    import idautils
    name = _require_param(params, "name")
    use_regex = params.get("regex", False)
    max_results = _clamp_int(params, "max_results", DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS)
    try:
        pattern = re.compile(name) if use_regex else None
    except re.error as e:
        raise RpcError("INVALID_PARAMS", f"Invalid regex: {e}")
    matches = []
    for ea in idautils.Functions():
        fn = cached_func_name(ea)
        if pattern:
            if pattern.search(fn):
                matches.append({"addr": _fmt_addr(ea), "name": fn})
        else:
            if name.lower() in fn.lower():
                matches.append({"addr": _fmt_addr(ea), "name": fn})
        if len(matches) >= max_results:
            break
    return {"query": name, "total": len(matches), "matches": matches}


# ── Info API ─────────────────────────────────

def _extract_type_info(func_start_ea):
    """Extract function type info (return_type, cc, args) using the decompiler."""
    import ida_hexrays, ida_typeinf
    result = {"calling_convention": None, "return_type": None, "args": None}
    try:
        cfunc = ida_hexrays.decompile(func_start_ea)
        if not cfunc:
            return result
    except Exception:
        return result

    tif = cfunc.type
    fi = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fi):
        return result

    try:
        rettype = tif.get_rettype()
        result["return_type"] = str(rettype) if rettype else None
    except Exception:
        pass

    try:
        cc = fi.cc & ida_typeinf.CM_CC_MASK
        cc_names = {
            ida_typeinf.CM_CC_CDECL: "__cdecl",
            ida_typeinf.CM_CC_STDCALL: "__stdcall",
            ida_typeinf.CM_CC_PASCAL: "__pascal",
            ida_typeinf.CM_CC_FASTCALL: "__fastcall",
            ida_typeinf.CM_CC_THISCALL: "__thiscall",
        }
        result["calling_convention"] = cc_names.get(cc, f"cc_{cc:#x}")
    except Exception:
        pass

    try:
        args = []
        for i in range(fi.size()):
            fa = fi[i]
            args.append({"name": fa.name or f"a{i+1}", "type": str(fa.type)})
        result["args"] = args
    except Exception:
        pass

    return result


def _handle_stack_frame(params):
    """Get stack frame layout with local variables and arguments (IDA 9.x API)."""
    import idc, ida_frame, ida_typeinf
    ea = _resolve_addr(_require_param(params, "addr"))
    func = _require_function(ea)

    tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(tif, func):
        raise RpcError("NO_FRAME", f"No stack frame for function at {_fmt_addr(ea)}")

    frame_size = ida_frame.get_frame_size(func)
    retaddr_size = ida_frame.get_frame_retsize(func)
    off_lvars = ida_frame.frame_off_lvars(func)
    off_retaddr = ida_frame.frame_off_retaddr(func)
    off_args = ida_frame.frame_off_args(func)
    locals_size = off_retaddr - off_lvars
    args_size = frame_size - off_args

    udt = ida_typeinf.udt_type_data_t()
    members = []
    if tif.get_udt_details(udt):
        for i in range(len(udt)):
            m = udt[i]
            off_bytes = m.offset // 8
            size_bytes = max(1, m.size // 8)
            mtype = str(m.type) if m.type else ""
            if off_bytes < off_retaddr:
                kind = "local"
            elif off_bytes < off_args:
                kind = "retaddr"
            else:
                kind = "arg"
            sp_off = off_bytes - off_retaddr
            members.append({
                "name": m.name or f"var_{off_bytes:X}",
                "offset": off_bytes, "size": size_bytes,
                "type": mtype, "kind": kind, "sp_offset": sp_off,
            })

    return {
        "addr": _fmt_addr(func.start_ea),
        "name": idc.get_func_name(func.start_ea) or "",
        "frame_size": frame_size,
        "locals_size": locals_size,
        "args_size": args_size,
        "retaddr_size": retaddr_size,
        "member_count": len(members),
        "members": members,
        "hint": "member_count is int. Use members array for stack layout details.",
    }


def _handle_switch_table(params):
    """Analyze switch/jump table at address (IDA 9.x API)."""
    import idc, ida_nalt, ida_bytes, idautils
    ea = _resolve_addr(_require_param(params, "addr"))
    func = _require_function(ea)

    switches = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        si = ida_nalt.get_switch_info(head)
        if not si:
            continue
        jt_size = si.get_jtable_size()
        elem_size = si.get_jtable_element_size()
        cases = []
        has_base = False
        try:
            has_base = bool(si.elbase != 0)
        except Exception:
            pass
        for i in range(jt_size):
            addr = si.jumps + i * elem_size
            if elem_size == 8:
                target_off = ida_bytes.get_qword(addr)
            elif elem_size == 2:
                target_off = ida_bytes.get_word(addr)
                if has_base and target_off >= 0x8000:
                    target_off -= 0x10000
            else:
                target_off = ida_bytes.get_dword(addr)
                if has_base and target_off >= 0x80000000:
                    target_off -= 0x100000000
            target = (si.elbase + target_off) if has_base else target_off
            cases.append({"index": i, "target": _fmt_addr(target)})
        default_ea = si.defjump
        bad = {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0}
        switches.append({
            "addr": _fmt_addr(head),
            "case_count": jt_size,
            "default": _fmt_addr(default_ea) if default_ea not in bad else None,
            "cases": cases,
        })

    if not switches:
        raise RpcError("NO_SWITCH", f"No switch tables found in function at {_fmt_addr(func.start_ea)}")

    return {
        "addr": _fmt_addr(func.start_ea),
        "name": idc.get_func_name(func.start_ea) or "",
        "switch_count": len(switches),
        "switches": switches,
        "hint": "switch_count is int. Each switch has case_count (int) and cases (list).",
    }


def _handle_get_func_info(params):
    import idc, ida_funcs
    ea = _resolve_addr(params.get("addr"))
    func = ida_funcs.get_func(ea)
    if not func:
        raise RpcError("NOT_A_FUNCTION", f"No function at {_fmt_addr(ea)}")
    result = {
        "addr": _fmt_addr(func.start_ea),
        "name": idc.get_func_name(func.start_ea) or "",
        "start_ea": _fmt_addr(func.start_ea),
        "end_ea": _fmt_addr(func.end_ea),
        "size": func.size(),
        "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
        "flags": _fmt_addr(func.flags),
        "decompiler_available": _fw._decompiler_available,
        "calling_convention": None, "return_type": None, "args": None,
    }
    if _fw._decompiler_available:
        result.update(_extract_type_info(func.start_ea))
    return result


def _handle_get_imagebase(params):
    import ida_nalt
    return {"imagebase": _fmt_addr(ida_nalt.get_imagebase())}


def _handle_get_bytes(params):
    import ida_bytes
    import base64
    ea = _resolve_addr(params.get("addr"))
    try:
        size = int(params.get("size", 16))
    except (ValueError, TypeError):
        raise RpcError("INVALID_PARAMS", "size must be a positive integer")
    if size < 0 or size > MAX_READ_BYTES:
        raise RpcError("INVALID_PARAMS", f"size must be <= {MAX_READ_BYTES}")
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None:
        raise RpcError("READ_FAILED", f"Cannot read {size} bytes at {_fmt_addr(ea)}")
    return {
        "addr": _fmt_addr(ea), "size": len(raw),
        "hex": _bytes_to_hex(raw),
        "raw_b64": base64.b64encode(raw).decode("ascii"),
    }


def _handle_find_bytes(params):
    import ida_bytes, idaapi
    pattern = _require_param(params, "pattern")
    max_results = _clamp_int(params, "max_results", DEFAULT_FIND_MAX, MAX_FIND_RESULTS)
    ea = _resolve_start_addr(params)
    matches = []
    for _ in range(max_results):
        ea = ida_bytes.find_bytes(pattern, ea)
        if ea is None or ea == idaapi.BADADDR:
            break
        matches.append(_fmt_addr(ea))
        ea += max(1, len(pattern.split()) if isinstance(pattern, str) else 1)
    return {"pattern": pattern, "total": len(matches), "matches": matches}
