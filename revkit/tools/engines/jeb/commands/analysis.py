"""Analysis commands -- decompile, classes, strings, methods, etc."""

import json
import logging
import os

from ..core import (
    _rpc_call, _opt, _truncate, _log_ok, _log_err, _log_info, _log_warn,
    _save_local, _is_md_out, _maybe_output_param,
    _check_inline_limit, _md_decompile,
    _build_params,
)
from ...base import CmdContext

log = logging.getLogger(__name__)


# =============================================================
# Shared helpers (used by other submodules via cross-module import)
# =============================================================

def _output_text(args, config, text):
    """Print or save text: --out saves to file, otherwise inline with limit."""
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, text)
    else:
        output, _ = _check_inline_limit(text, config)
        print(output)


def _print_or_saved(config, text, saved_to):
    """If server saved to file, log it; otherwise print inline with limit."""
    if saved_to:
        _log_ok(f"Saved to: {saved_to}")
    else:
        output, _ = _check_inline_limit(text, config)
        print(output)


def _safe_len(val):
    """Get count from a value (int or list/dict -> len)."""
    return val if isinstance(val, int) else len(val) if val else 0


def _resolve_short_name(args, config, name):
    """#19: Resolve short class name (e.g. 'MainActivity') to full signature.

    If name doesn't look like a DEX signature (Lcom/.../Foo;), search for it.
    """
    if name.startswith("L") and name.endswith(";"):
        return name  # already full sig
    if "->" in name or "(" in name:
        return name  # method sig
    # Try search
    r = _rpc_call(args, config, "search_classes", {"keyword": name, "max_results": 10})
    if not r:
        return name
    matches = r.get("matches", [])
    if not matches:
        return name
    if len(matches) == 1:
        _log_info(f"Resolved: {name} -> {matches[0]['sig']}")
        return matches[0]["sig"]
    # Multiple matches: try exact class name match
    for m in matches:
        sig = m.get("sig", "")
        # Extract simple name: Lcom/example/Foo; -> Foo
        simple = sig.rstrip(";").rsplit("/", 1)[-1]
        if simple.lower() == name.lower():
            _log_info(f"Resolved: {name} -> {sig}")
            return sig
    # Show ambiguous matches
    _log_warn(f"Ambiguous name '{name}', {len(matches)} matches:")
    for m in matches[:5]:
        print(f"    {m.get('sig', '')}")
    return matches[0]["sig"] if matches else name


def _cmd_search(args, config, rpc_method, param_key, query_attr, fmt_fn):
    """Shared search handler for classes/methods."""
    query = getattr(args, query_attr)
    p = {param_key: query}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    # #30: regex support
    if _opt(args, 'regex', False):
        p["regex"] = True
    r = _rpc_call(args, config, rpc_method, p)
    if not r:
        return
    lines = [f"Query: '{query}' ({r.get('total', 0)} matches)"]
    for m in r.get("matches", []):
        lines.append(fmt_fn(m))
    _output_text(args, config, "\n".join(lines))


def _cmd_class_members(args, config, rpc_method, items_key, label, type_key):
    """Shared handler for methods_of_class / fields_of_class."""
    p = {"sig": args.class_sig}
    if _opt(args, 'out'):
        p["output"] = args.out
    r = _rpc_call(args, config, rpc_method, p)
    if not r:
        return
    items = r.get(items_key, [])
    lines = [f"Class: {r.get('class_sig', '')} ({len(items)} {label})"]
    for m in items:
        access = f"0x{m.get('access', 0):04x}" if 'access' in m else ""
        lines.append(f"  {m.get('sig', ''):<60}  {access}  {m.get(type_key, '')}")
    _output_text(args, config, "\n".join(lines))


# =============================================================
# Decompile / Disasm
# =============================================================

def cmd_method(ctx: CmdContext):
    """Decompile a single method to Java source."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_method: method_sig=%s", args.method_sig)
    p = {"method_sig": args.method_sig}
    out_path = _opt(args, 'out')
    if out_path:
        p["output"] = os.path.abspath(out_path)
    # #25: method --with-xrefs
    if _opt(args, 'with_xrefs', False):
        p["with_xrefs"] = True
    r = _rpc_call(args, config, "get_method_by_name", p)
    if not r:
        log.warning("cmd_method: RPC returned None for %s", args.method_sig)
        return
    code = r.get("code", "")
    sig = r.get("method_sig", "")
    output = f"// {sig}\n{code}"
    # #25: append xrefs info
    if _opt(args, 'with_xrefs', False):
        for label, key in [("Callers", "callers"), ("Callees", "callees"),
                            ("Fields", "fields_ref")]:
            items = r.get(key, [])
            if items:
                output += f"\n\n// --- {label} ({len(items)}) ---"
                for c in items:
                    ref = c.get('method_sig', c.get('sig', c.get('address', '')))
                    output += f"\n//   {ref}"
    _print_or_saved(config, output, r.get("saved_to"))


def cmd_decompile(ctx: CmdContext):
    """Decompile a class or method to Java source."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_decompile: sig=%s", args.sig)
    with_xrefs = _opt(args, 'with_xrefs', False)
    md_out = _is_md_out(args)
    sig = _resolve_short_name(args, config, args.sig)
    # #44: auto filename if --auto-out
    if _opt(args, 'auto_out', False) and not _opt(args, 'out'):
        clean = sig.strip("L;").replace("/", "_").replace("->", "_")
        args.out = f"{clean}.java"
    p = {"sig": sig}
    _maybe_output_param(args, p, md_out)
    method = "decompile_with_xrefs" if with_xrefs else "decompile"
    r = _rpc_call(args, config, method, p)
    if not r:
        log.warning("cmd_decompile: RPC returned None for %s", sig)
        return
    log.debug("cmd_decompile: got code for %s, len=%d", sig, len(r.get("code", "")))
    if md_out:
        _save_local(args.out, _md_decompile(r, with_xrefs))
        return
    code = r.get("code", "")
    sig = r.get("class_sig", r.get("sig", ""))
    # #20: --line-numbers
    if _opt(args, 'line_numbers', False) and code:
        numbered = []
        for i, line in enumerate(code.split("\n"), 1):
            numbered.append(f"{i:4d} | {line}")
        code = "\n".join(numbered)
    header = f"// {sig}"
    output = f"{header}\n{code}"
    if with_xrefs:
        for label, key in [("Callers", "callers"), ("Callees", "callees")]:
            items = r.get(key, [])
            if items:
                output += f"\n\n// --- {label} ({len(items)}) ---"
                output += "".join(
                    f"\n//   {c.get('method_sig', '')}  [{c.get('type', '')}]"
                    for c in items)
    # #22: --no-limit bypasses inline truncation
    if _opt(args, 'no_limit', False) and not r.get("saved_to"):
        print(output)
    else:
        _print_or_saved(config, output, r.get("saved_to"))


def cmd_decompile_diff(ctx: CmdContext):
    """#24: Compare current decompile with a saved file (rename 전후 비교)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_decompile_diff: sig=%s diff_file=%s", args.sig, args.diff_file)
    import difflib
    sig = _resolve_short_name(args, config, args.sig)
    diff_file = args.diff_file
    if diff_file is None:
        # Remote mode or no file: use server-side previous version comparison
        r = _rpc_call(args, config, "decompile_diff", {"sig": sig})
        if r:
            if r.get("diff"):
                print(r["diff"])
            elif r.get("message"):
                _log_info(r["message"])
            if r.get("code") and _opt(args, 'out'):
                _save_local(_opt(args, 'out'), r["code"])
        return
    if not os.path.isfile(diff_file):
        _log_err(f"File not found: {diff_file}")
        return
    try:
        with open(diff_file, "r", encoding="utf-8") as f:
            old_lines = f.readlines()
    except UnicodeDecodeError:
        with open(diff_file, "r", encoding="utf-8", errors="replace") as f:
            old_lines = f.readlines()
    # Get current decompile
    r = _rpc_call(args, config, "decompile", {"sig": sig})
    if not r:
        return
    new_code = r.get("code", "")
    new_lines = (f"// {sig}\n{new_code}").splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile=os.path.basename(diff_file),
        tofile=f"current ({sig})",
        lineterm="",
    ))
    if not diff:
        _log_info("No differences found")
        return
    output = "\n".join(diff)
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, output)
    else:
        print(output)


def cmd_decompile_batch(ctx: CmdContext):
    """Decompile multiple classes/methods at once (max 20)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_decompile_batch: %d sigs", len(args.sigs))
    md_out = _is_md_out(args)
    sigs = args.sigs
    if len(sigs) > 20:
        _log_warn("Limiting to first 20 signatures")
        sigs = sigs[:20]
    p = {"class_sigs": sigs}
    _maybe_output_param(args, p, md_out)
    r = _rpc_call(args, config, "decompile_batch", p)
    if not r:
        log.warning("cmd_decompile_batch: RPC returned None")
        return
    results = r.get("results", [])
    log.debug("cmd_decompile_batch: %d/%d succeeded", r.get('success', 0), r.get('total', 0))
    total, success, failed = r.get('total', 0), r.get('success', 0), r.get('failed', 0)
    if md_out:
        parts = [f"# Batch Decompile ({success}/{total})\n"]
        for func in results:
            sig = func.get('sig', '?')
            if "code" in func:
                parts.append(f"## {sig}\n\n```java\n{func['code']}\n```\n")
            else:
                parts.append(f"## {sig}\n\nERROR: {func.get('error', '?')}\n")
        _save_local(args.out, "\n".join(parts))
        return
    lines = [f"Total: {total}, Success: {success}, Failed: {failed}"]
    for func in results:
        sig = func.get('sig', '?')
        if "code" in func:
            lines.append(f"\n// -- {sig} --")
            lines.append(func["code"])
        else:
            lines.append(f"\n// -- {sig} -- ERROR: {func.get('error', '?')}")
    _print_or_saved(config, "\n".join(lines), r.get("saved_to"))


def cmd_decompile_all(ctx: CmdContext):
    """Decompile all classes to file(s)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_decompile_all: out=%s", args.out)
    out_path = args.out
    split = _opt(args, 'split', False)
    # #23: --package filter (converts to DEX-style filter)
    pkg = _opt(args, 'package')
    filt = _opt(args, 'filter', '')
    if pkg and not filt:
        filt = pkg.replace(".", "/")
    p = {
        "output": out_path,
        "filter": filt,
    }
    if split:
        p["split"] = True
    r = _rpc_call(args, config, "decompile_all", p)
    if not r:
        log.warning("cmd_decompile_all: RPC returned None")
        return
    log.debug("cmd_decompile_all: %d/%d classes, saved to %s",
              r.get('success', 0), r.get('total', 0), r.get('saved_to', ''))
    print(f"  Decompiled: {r.get('success', 0)}/{r.get('total', 0)} classes, "
          f"Failed: {r.get('failed', 0)}")
    saved = r.get("saved_to")
    if not saved and out_path and r.get("code"):
        _save_local(out_path, r["code"])
        saved = out_path
    print(f"  Saved to: {saved or '(not saved)'}")


def cmd_smali(ctx: CmdContext):
    """Get Smali bytecode for a class or specific method (#21)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_smali: class_sig=%s", args.class_sig)
    sig = args.class_sig
    p = {}
    # #21: detect if sig is a method signature (contains -> or ())
    if "->" in sig or "(" in sig:
        p["method_sig"] = sig
    else:
        p["class_sig"] = sig
    _maybe_output_param(args, p)
    r = _rpc_call(args, config, "get_smali", p)
    if not r:
        return
    _print_or_saved(config, r.get("smali", ""), r.get("saved_to"))


# =============================================================
# Classes / Strings / Methods listing
# =============================================================

def cmd_strings(ctx: CmdContext):
    """List strings with extended filters (#13 min-len, #14 regex, #15 encoding)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_strings: filters min_len=%s regex=%s encoding=%s",
              _opt(args, 'min_len'), _opt(args, 'regex'), _opt(args, 'encoding'))
    from ..core import _LIST_PARAM_MAP, STRING_DISPLAY_LIMIT
    base_params = _build_params(args, _LIST_PARAM_MAP)
    # #13: min_len
    min_len = _opt(args, 'min_len')
    if min_len:
        base_params["min_len"] = min_len
    # #14: regex
    regex = _opt(args, 'regex')
    if regex:
        base_params["regex"] = regex
    # #15: encoding
    encoding = _opt(args, 'encoding')
    if encoding:
        base_params["encoding"] = encoding
    r = _rpc_call(args, config, "get_strings", base_params)
    if not r:
        log.warning("cmd_strings: RPC returned None")
        return
    log.debug("cmd_strings: got %d strings (total=%d)", r.get('count', 0), r.get('total', 0))
    if _opt(args, 'count_only', False):
        print(f"Total: {r.get('total', 0)}")
        return
    print(f"Total: {r['total']} (showing {r['count']})")
    for d in r.get("data", []):
        print(f"  {d.get('index', '')}  {_truncate(d.get('value', ''), STRING_DISPLAY_LIMIT)}")


def cmd_classes(ctx: CmdContext):
    """List classes with optional --tree view (#12)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_classes: tree=%s", _opt(args, 'tree', False))
    from ..core import _LIST_PARAM_MAP
    r = _rpc_call(args, config, "get_classes", _build_params(args, _LIST_PARAM_MAP))
    if not r:
        log.warning("cmd_classes: RPC returned None")
        return
    log.debug("cmd_classes: got %d classes (total=%d)", len(r.get('data', [])), r.get('total', 0))
    if _opt(args, 'count_only', False):
        print(f"Total: {r.get('total', 0)}")
        return
    data = r.get("data", [])
    # #12: --tree view
    if _opt(args, 'tree', False):
        tree = {}
        for d in data:
            sig = d.get("sig", "")
            # Lcom/example/Foo; -> com.example.Foo
            clean = sig.strip("L;").replace("/", ".")
            parts = clean.rsplit(".", 1)
            pkg = parts[0] if len(parts) > 1 else "(default)"
            cls_name = parts[-1]
            tree.setdefault(pkg, []).append(cls_name)
        for pkg in sorted(tree.keys()):
            classes = sorted(tree[pkg])
            print(f"  {pkg}/ ({len(classes)})")
            for c in classes:
                print(f"    {c}")
        return
    # Normal flat list
    print(f"Total: {r['total']} (showing {r['count']} from offset {r['offset']})")
    for d in data:
        print(f"  {d.get('sig', '')}  {d.get('current_name', d.get('name', '')):<50}  access=0x{d.get('access', 0):04x}")


def cmd_methods_of_class(ctx: CmdContext):
    """List all methods of a class."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_methods_of_class: class_sig=%s", args.class_sig)
    _cmd_class_members(args, config, "get_methods_of_class",
                       "methods", "methods", "return_type")


def cmd_fields_of_class(ctx: CmdContext):
    """List all fields of a class."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_fields_of_class: class_sig=%s", args.class_sig)
    _cmd_class_members(args, config, "get_fields_of_class",
                       "fields", "fields", "type")


def cmd_method_info(ctx: CmdContext):
    """Show detailed information about a method."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_method_info: method_sig=%s", args.method_sig)
    r = _rpc_call(args, config, "get_method_info", {"sig": args.method_sig})
    if not r:
        return
    for label, val in [("Signature", r.get('method_sig', r.get('sig', ''))),
                        ("Name", r.get('name', '')),
                        ("Class", r.get('class_sig', '')),
                        ("Return type", r.get('return_type', '')),
                        ("Access", f"0x{r.get('access_flags', r.get('access', 0)):04x}")]:
        print(f"  {label + ':':<14} {val}")
    params = r.get("params") or r.get("parameters") or []
    if params:
        print(f"  Parameters:")
        for p in params:
            print(f"    {p.get('type', ''):<30}  {p.get('name', '')}")


def cmd_methods(ctx: CmdContext):
    """List methods — either RPC methods (no class_sig) or DEX methods of a class."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_methods: class_sig=%s", _opt(args, 'class_sig'))
    class_sig = _opt(args, 'class_sig')
    if class_sig:
        # Delegate to methods_of_class
        cmd_methods_of_class(ctx)
        return
    # No class specified: list RPC methods
    r = _rpc_call(args, config, "methods")
    if not r:
        return
    for m in r.get("methods", []):
        print(f"  {m.get('name', ''):<30}  {m.get('description', '')}")


def cmd_native_methods(ctx: CmdContext):
    """List all native method declarations with SO library mapping."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_native_methods: filter=%s", _opt(args, 'filter'))
    p = _build_params(args, {"filter": "filter"})
    r = _rpc_call(args, config, "native_methods", p)
    if not r:
        log.warning("cmd_native_methods: RPC returned None")
        return
    methods = r.get("data", [])
    log.debug("cmd_native_methods: got %d methods, %d libraries", len(methods), len(r.get("libraries", [])))
    total = r.get("total", len(methods))
    libs = r.get("libraries", [])

    if _opt(args, "json_output"):
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    lines = []
    lines.append(f"Native Methods ({total})")
    if libs:
        lines.append(f"  Libraries: {', '.join(libs)}")
    lines.append("")

    # Group by class
    by_class = {}
    for m in methods:
        cls = m.get("class_sig", "?")
        by_class.setdefault(cls, []).append(m)

    for cls_sig, cls_methods in by_class.items():
        lib_str = cls_methods[0].get("lib", "")
        hdr = cls_sig
        if lib_str:
            hdr += f"  [{lib_str}]"
        lines.append(hdr)
        for m in cls_methods:
            params_str = m.get("params", "")
            ret = m.get("return_type", "void")
            lines.append(f"  {m.get('name', '?')}({params_str}) -> {ret}")
        lines.append("")

    text = "\n".join(lines)
    _output_text(args, config, text)
