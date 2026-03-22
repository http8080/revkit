"""Search commands -- search classes/methods/code, strings xrefs."""

import json
import logging

from ..core import (
    _rpc_call, _opt, _truncate, _log_info,
    _build_params, _save_local,
)
from .analysis import _cmd_search, _output_text
from ...base import CmdContext

log = logging.getLogger(__name__)


def cmd_search_classes(ctx: CmdContext):
    """Search classes by keyword."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_search_classes: keyword=%s", args.keyword)
    _cmd_search(args, config, "search_classes", "keyword", "keyword",
                lambda m: f"  {m.get('sig', '')}  {m.get('name', '')}")


def cmd_search_methods(ctx: CmdContext):
    """Search methods by name."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_search_methods: name=%s", args.name)
    _cmd_search(args, config, "search_methods", "name", "name",
                lambda m: f"  {m.get('sig', '')}  {m.get('class_name', '')}.{m.get('name', '')}")


def cmd_search_code(ctx: CmdContext):
    """Search within decompiled source code."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_search_code: query=%s regex=%s", _opt(args, 'query'), _opt(args, 'regex', False))
    p = _build_params(args, {"query": "query", "max_results": "max_results",
                              "case_sensitive": "case_sensitive"})
    # #27: context lines
    ctx_lines = _opt(args, 'context')
    if ctx_lines:
        p["context_lines"] = ctx_lines
    # #26: regex
    if _opt(args, 'regex', False):
        p["regex"] = True
    # #28: package filter (convert dot to slash for DEX sigs)
    pkg = _opt(args, 'package')
    if pkg:
        p["package"] = pkg.replace(".", "/")
    r = _rpc_call(args, config, "search_code", p)
    if not r:
        log.warning("cmd_search_code: RPC returned None")
        return
    matches = r.get("matches", r.get("results", []))
    log.debug("cmd_search_code: found %d matches", r.get('total', 0))
    print(f"  Query: \"{r.get('query', '')}\"  Found: {r.get('total', 0)} matches  "
          f"(scanned: {r.get('classes_searched', r.get('classes_scanned', 0))})")
    for m in matches:
        # #27: show context if available
        ctx_content = m.get("context")
        if ctx_content:
            print(f"  --- {m.get('class_sig', '')} ---")
            for cl in ctx_content:
                marker = ">" if cl.get("match") else " "
                print(f"  {marker} {cl.get('line_no', ''):4d} | {cl.get('line', '')}")
            print()
        else:
            print(f"    {m.get('class_sig', '')}  L{m.get('line_no', '?')}: {m.get('line', m.get('text', ''))}")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))


def cmd_strings_xrefs(ctx: CmdContext):
    """List strings with their cross-references."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_strings_xrefs: filter=%s", _opt(args, 'filter'))
    p = _build_params(args, {"filter": "filter", "max": "max_results",
                              "min_refs": "min_refs"})
    r = _rpc_call(args, config, "strings_xrefs", p)
    if not r:
        log.warning("cmd_strings_xrefs: RPC returned None")
        return
    log.debug("cmd_strings_xrefs: got %d strings", r.get('total', 0))
    lines = [f"Strings with xrefs ({r.get('total', 0)}):"]
    for entry in r.get("data", r.get("strings", [])):
        xrefs = entry.get("xrefs", entry.get("refs", []))
        val = _truncate(entry.get("value", ""), 60)
        lines.append(f"  \"{val}\" ({len(xrefs)} refs)")
        for ref in xrefs:
            if isinstance(ref, dict):
                # #31: show resolved method name and class
                method_sig = ref.get('method_sig', '')
                class_sig = ref.get('class_sig', '')
                if method_sig:
                    lines.append(f"    <- {method_sig}")
                elif class_sig:
                    lines.append(f"    <- {class_sig}")
                else:
                    lines.append(f"    <- {ref.get('address', ref.get('sig', ''))}")
            else:
                lines.append(f"    <- {ref}")
    text = "\n".join(lines)
    _output_text(args, config, text)
