"""Analysis proxy commands — decompile, disasm, xrefs, exec, summary, shell."""

import json
import os

from ..core import (
    _rpc_call, _build_params, _opt, _truncate, _save_local,
    _log_ok, _log_err, _log_info,
    _is_md_out, _maybe_output_param, _check_inline_limit,
    _md_decompile, _md_decompile_batch, _md_summary,
    post_rpc, _resolve_ready,
)
from ...base import CmdContext
from ....core.utils import resolve_script_path

import logging
log = logging.getLogger(__name__)


def cmd_proxy_segments(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_segments: fetching segments")
    p = _build_params(args, {"out": "output"})
    r = _rpc_call(args, config, "get_segments", p)
    if not r:
        log.debug("cmd_proxy_segments: RPC returned None")
        return
    for d in r.get("data", []):
        print(f"  {d['start_addr']}-{d['end_addr']}  {d.get('name') or '':<12}  "
              f"{d.get('class') or '':<8}  size={d.get('size') or 0:<8}  {d.get('perm') or ''}")


def cmd_proxy_decompile(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_decompile: addr=%s", args.addr)
    with_xrefs = _opt(args, 'with_xrefs', False)
    raw = _opt(args, 'raw', False)
    md_out = _is_md_out(args)
    p = {"addr": args.addr}
    if raw:
        p["raw"] = True
    _maybe_output_param(args, p, md_out)
    method = "decompile_with_xrefs" if with_xrefs else "decompile"
    r = _rpc_call(args, config, method, p)
    if not r:
        log.debug("cmd_proxy_decompile: RPC returned None")
        return
    log.debug("cmd_proxy_decompile: got func=%s addr=%s", r.get("name", "?"), r.get("addr", "?"))
    if md_out:
        _save_local(args.out, _md_decompile(r, with_xrefs))
        return
    code = r.get("code", "")
    if raw:
        output = code
    else:
        header = f"// {r.get('name', '')} @ {r.get('addr', '')}"
        output = f"{header}\n{code}"
    if with_xrefs and not raw:
        callers = r.get("callers", [])
        callees = r.get("callees", [])
        if callers:
            output += f"\n\n// --- Callers ({len(callers)}) ---"
            for c in callers:
                output += f"\n//   {c['from_addr']}  {c['from_name']:<30}  [{c['type']}]"
        if callees:
            output += f"\n\n// --- Callees ({len(callees)}) ---"
            for c in callees:
                output += f"\n//   {c['to_addr']}  {c['to_name']:<30}  [{c['type']}]"
    if r.get("saved_to"):
        _log_ok(f"Saved to: {r['saved_to']}")
    else:
        output, _ = _check_inline_limit(output, config)
        print(output)


def cmd_proxy_decompile_batch(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_decompile_batch: addrs=%s", args.addrs)
    md_out = _is_md_out(args)
    p = {"addrs": args.addrs}
    _maybe_output_param(args, p, md_out)
    r = _rpc_call(args, config, "decompile_batch", p)
    if not r:
        log.debug("cmd_proxy_decompile_batch: RPC returned None")
        return
    log.debug("cmd_proxy_decompile_batch: total=%s success=%s failed=%s", r.get("total", 0), r.get("success", 0), r.get("failed", 0))
    if md_out:
        _save_local(args.out, _md_decompile_batch(r))
        return
    lines = [f"Total: {r.get('total', 0)}, Success: {r.get('success', 0)}, Failed: {r.get('failed', 0)}"]
    for func in r.get("functions", []):
        if "code" in func:
            lines.append(f"\n// -- {func['name']} ({func['addr']}) --")
            lines.append(func["code"])
        else:
            lines.append(f"\n// -- {func.get('addr', '?')} -- ERROR: {func.get('error', '?')}")
    if r.get("saved_to"):
        print(lines[0])  # summary line only
        _log_ok(f"Saved to: {r['saved_to']}")
    else:
        output = "\n".join(lines)
        output, _ = _check_inline_limit(output, config)
        print(output)


def cmd_proxy_disasm(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_disasm: addr=%s", args.addr)
    p = {"addr": args.addr}
    p.update(_build_params(args, {"count": "count", "out": "output"}))
    r = _rpc_call(args, config, "disasm", p)
    if not r:
        log.debug("cmd_proxy_disasm: RPC returned None")
        return
    log.debug("cmd_proxy_disasm: got %d lines", len(r.get("lines", [])))
    for ln in r.get("lines", []):
        print(f"  {ln['addr']}  {ln.get('bytes', ''):<24}  {ln['insn']}")


def cmd_proxy_xrefs(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_xrefs: addr=%s direction=%s", args.addr, _opt(args, 'direction', 'to'))
    direction = _opt(args, 'direction', 'to')
    p = {"addr": args.addr}
    if direction in ("to", "both"):
        r = _rpc_call(args, config, "get_xrefs_to", p)
        if r:
            print(f"Xrefs TO {args.addr} ({r.get('total', 0)})")
            for ref in r.get("refs", []):
                print(f"  {ref['from_addr']}  {ref.get('from_name', ''):<30}  {ref['type']}")
    if direction in ("from", "both"):
        if direction == "both":
            print()
        r = _rpc_call(args, config, "get_xrefs_from", p)
        if r:
            print(f"Xrefs FROM {args.addr} ({r.get('total', 0)})")
            for ref in r.get("refs", []):
                print(f"  {ref['to_addr']}  {ref.get('to_name', ''):<30}  {ref['type']}")


def cmd_proxy_callers(ctx: CmdContext):
    """Shortcut: xrefs --direction to (who calls this)."""
    ctx.args.direction = "to"
    cmd_proxy_xrefs(ctx)


def cmd_proxy_callees(ctx: CmdContext):
    """Shortcut: xrefs --direction from (what this calls)."""
    ctx.args.direction = "from"
    cmd_proxy_xrefs(ctx)


def cmd_proxy_find_func(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_find_func: name=%s", args.name)
    p = {"name": args.name}
    if _opt(args, 'regex', False): p["regex"] = True
    if _opt(args, 'max'): p["max_results"] = args.max
    r = _rpc_call(args, config, "find_func", p)
    if not r:
        log.debug("cmd_proxy_find_func: RPC returned None")
        return
    log.debug("cmd_proxy_find_func: got %d matches", r.get("total", 0))
    lines = [f"Query: '{r.get('query', '?')}' ({r.get('total', 0)} matches)"]
    for m in r.get("matches", []):
        lines.append(f"  {m.get('addr', '?')}  {m.get('name', '?')}")
    text = "\n".join(lines)
    out = _opt(args, 'out')
    if out:
        _save_local(out, text)
    else:
        print(text)


def cmd_proxy_func_info(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_func_info: addr=%s", args.addr)
    r = _rpc_call(args, config, "get_func_info", {"addr": args.addr})
    if not r: return
    print(f"  Name:       {r.get('name')}")
    print(f"  Address:    {r.get('start_ea')} - {r.get('end_ea')}")
    print(f"  Size:       {r.get('size')}")
    print(f"  Thunk:      {r.get('is_thunk')}")
    if r.get("calling_convention"):
        print(f"  Convention: {r['calling_convention']}")
    if r.get("return_type"):
        print(f"  Return:     {r['return_type']}")
    if r.get("args"):
        arg_strs = ["{} {}".format(a["type"], a["name"]) for a in r["args"]]
        print(f"  Args:       {', '.join(arg_strs)}")


def cmd_proxy_imagebase(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_imagebase: fetching imagebase")
    r = _rpc_call(args, config, "get_imagebase")
    if r:
        print(f"  Imagebase: {r['imagebase']}")


def cmd_proxy_bytes(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_bytes: addr=%s size=%s", args.addr, args.size)
    r = _rpc_call(args, config, "get_bytes", {"addr": args.addr, "size": args.size})
    if not r: return
    print(f"  Address: {r['addr']}")
    print(f"  Hex:     {r['hex']}")
    print(f"  Base64:  {r['raw_b64']}")


def cmd_proxy_find_pattern(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_find_pattern: pattern=%s", args.pattern)
    p = {"pattern": args.pattern}
    if _opt(args, 'max'): p["max_results"] = args.max
    r = _rpc_call(args, config, "find_bytes", p)
    if not r:
        log.debug("cmd_proxy_find_pattern: RPC returned None")
        return
    log.debug("cmd_proxy_find_pattern: got %d matches", r.get("total", 0))
    lines = [f"Pattern: '{r.get('pattern', '?')}' ({r.get('total', 0)} matches)"]
    for addr in r.get("matches", []):
        lines.append(f"  {addr}")
    text = "\n".join(lines)
    out = _opt(args, 'out')
    if out:
        _save_local(out, text)
    else:
        print(text)


def cmd_proxy_comments(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_comments: addr=%s", args.addr)
    r = _rpc_call(args, config, "get_comments", {"addr": args.addr})
    if not r: return
    print(f"  Address:    {r['addr']}")
    print(f"  Comment:    {r.get('comment', '')}")
    print(f"  Repeatable: {r.get('repeatable_comment', '')}")
    print(f"  Function:   {r.get('func_comment', '')}")


def cmd_proxy_methods(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_methods: listing RPC methods")
    r = _rpc_call(args, config, "methods")
    if not r: return
    for m in r.get("methods", []):
        print(f"  {m['name']:<20}  {m['description']}")


def cmd_proxy_save(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_save: saving database")
    r = _rpc_call(args, config, "save_db")
    if r:
        _log_ok(f"Database saved: {r.get('idb_path')}")


def cmd_proxy_exec(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    code = args.code
    # Resolve .py script path (supports short paths like "analysis/find_crypto.py")
    resolved = resolve_script_path(code, "ida", config)
    if resolved:
        with open(resolved, "r", encoding="utf-8") as f:
            code = f.read()
        log.debug("cmd_proxy_exec: loaded script %s (%d lines)", resolved, code.count("\n") + 1)
    else:
        log.debug("cmd_proxy_exec: inline code (%d chars)", len(code))
    p = {"code": code}
    _maybe_output_param(args, p)
    r = _rpc_call(args, config, "exec", p)
    if not r: return
    if r.get("stdout"):
        print(r["stdout"], end="")
    if r.get("stderr"):
        print(f"[stderr] {r['stderr']}", end="")


def cmd_proxy_summary(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_summary: fetching summary")
    r = _rpc_call(args, config, "summary")
    if not r:
        log.debug("cmd_proxy_summary: RPC returned None")
        return
    log.debug("cmd_proxy_summary: funcs=%s strings=%s imports=%s", r.get("func_count"), r.get("total_strings"), r.get("total_imports"))
    print(f"  Binary:      {r['binary']}")
    print(f"  Decompiler:  {r['decompiler']}")
    print(f"  IDA:         {r['ida_version']}")
    print(f"  Functions:   {r['func_count']}  (avg size: {r['avg_func_size']} bytes)")
    print(f"  Strings:     {r['total_strings']}")
    print(f"  Imports:     {r['total_imports']}")
    print(f"  Exports:     {r['export_count']}")
    print()
    print("  Segments:")
    for s in r.get("segments", []):
        print(f"    {s['start_addr']}-{s['end_addr']}  {s.get('name', ''):<12}  "
              f"size={s['size']:<8}  {s['perm']}")
    if r.get("top_import_modules"):
        print()
        print("  Top Import Modules:")
        for m in r["top_import_modules"]:
            print(f"    {m['module']:<30}  {m['count']} imports")
    if r.get("largest_functions"):
        print()
        print("  Largest Functions:")
        for f in r["largest_functions"]:
            print(f"    {f['addr']}  {f['name']:<40}  {f['size']} bytes")
    if r.get("strings_sample"):
        print()
        print(f"  Strings (first {len(r['strings_sample'])}):")
        for s in r["strings_sample"]:
            print(f"    {s['addr']}  {_truncate(s['value'], 60)}")


def cmd_shell(ctx: CmdContext):
    """Interactive IDA Python REPL."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_shell: starting interactive shell")
    iid, info, port = _resolve_ready(args, config)
    if not iid:
        return
    binary = os.path.basename(info.get("binary", "?"))
    _log_info(f"IDA Python Shell - {binary} ({iid})")
    _log_info("Type 'exit' or Ctrl+C to quit")
    print()
    while True:
        try:
            code = input(f"ida({binary})>>> ")
        except (EOFError, KeyboardInterrupt):
            _log_info("Shell closed")
            break
        if not code.strip():
            continue
        if code.strip() in ("exit", "quit"):
            _log_info("Shell closed")
            break
        # Multi-line: if line ends with ':', collect until blank line
        if code.rstrip().endswith(":"):
            lines = [code]
            while True:
                try:
                    line = input("... ")
                except (EOFError, KeyboardInterrupt):
                    break
                if not line.strip():
                    break
                lines.append(line)
            code = "\n".join(lines)
        resp = post_rpc(config, port, "exec", iid, {"code": code})
        if "error" in resp:
            _log_err(resp['error'].get('message', '?'))
        else:
            r = resp.get("result", {})
            if r.get("stdout"):
                print(r["stdout"], end="")
            if r.get("stderr"):
                print(f"[stderr] {r['stderr']}", end="")
