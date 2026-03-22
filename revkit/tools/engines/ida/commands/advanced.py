"""Advanced analysis commands — callgraph, cross-refs, decompile-all, search-code, etc."""

from ..core import (
    _rpc_call, _opt, _save_local, _truncate,
)
import json
import logging
from ...base import CmdContext

log = logging.getLogger(__name__)


def cmd_callgraph(ctx: CmdContext):
    """Generate function call graph."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_callgraph: addr=%s depth=%s direction=%s", args.addr, _opt(args, 'depth', 3), _opt(args, 'direction', 'callees'))
    fmt = _opt(args, 'format', 'mermaid') or 'mermaid'
    depth = _opt(args, 'depth', 3)
    direction = _opt(args, 'direction', 'callees')
    p = {"addr": args.addr, "depth": depth, "direction": direction}
    r = _rpc_call(args, config, "callgraph", p)
    if not r:
        log.debug("cmd_callgraph: RPC returned None")
        return
    log.debug("cmd_callgraph: nodes=%s edges=%s", r.get("nodes", 0), r.get("edges", 0))
    out_path = _opt(args, 'out')
    print(f"  Root: {r.get('root_name', '')} ({r.get('root', '')})")
    print(f"  Nodes: {r.get('nodes', 0)}, Edges: {r.get('edges', 0)}")
    if fmt == "dot":
        content = r.get("dot", "")
    else:
        content = r.get("mermaid", "")
    if out_path:
        _save_local(out_path, content)
    else:
        print()
        print(content)


def cmd_cross_refs(ctx: CmdContext):
    """Multi-level xref chain tracing."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_cross_refs: addr=%s depth=%s direction=%s", args.addr, _opt(args, 'depth', 3), _opt(args, 'direction', 'to'))
    p = {"addr": args.addr, "depth": _opt(args, 'depth', 3),
         "direction": _opt(args, 'direction', 'to')}
    r = _rpc_call(args, config, "cross_refs", p)
    if not r:
        log.debug("cmd_cross_refs: RPC returned None")
        return
    log.debug("cmd_cross_refs: nodes=%s edges=%s", r.get("nodes", 0), r.get("edges", 0))
    print(f"  Root: {r.get('root', '')}  Depth: {r.get('depth')}  Direction: {r.get('direction')}")
    print(f"  Nodes: {r.get('nodes', 0)}, Edges: {r.get('edges', 0)}")
    for entry in r.get("chain", []):
        indent = "  " * entry["level"]
        print(f"    {indent}{entry['addr']}  {entry['name']}")
    out_path = _opt(args, 'out')
    if out_path:
        fmt = _opt(args, 'format', 'mermaid')
        content = r.get("dot" if fmt == "dot" else "mermaid", "")
        _save_local(out_path, content)


def cmd_decompile_all(ctx: CmdContext):
    """Decompile all functions to .c file."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_decompile_all: out=%s", args.out)
    out_path = args.out
    split = _opt(args, 'split', False)
    p = {"output": out_path, "filter": _opt(args, 'filter', ''),
         "skip_thunks": not _opt(args, 'include_thunks', False),
         "skip_libs": not _opt(args, 'include_libs', False)}
    if split:
        p["split"] = True
    r = _rpc_call(args, config, "decompile_all", p)
    if not r:
        log.debug("cmd_decompile_all: RPC returned None")
        return
    log.debug("cmd_decompile_all: success=%d total=%d failed=%d", r.get("success", 0), r.get("total", 0), r.get("failed", 0))
    print(f"  Decompiled: {r.get('success', 0)}/{r.get('total', 0)} functions")
    print(f"  Failed: {r.get('failed', 0)}, Skipped: {r.get('skipped', 0)}")
    saved = r.get("saved_to")
    if not saved and out_path and r.get("code"):
        _save_local(out_path, r["code"])
        saved = out_path
    mode = "directory" if r.get("split") else "file"
    print(f"  Saved to ({mode}): {saved or '(not saved)'}")


def cmd_search_code(ctx: CmdContext):
    """Search within decompiled pseudocode."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_search_code: query=%s", args.query)
    p = {"query": args.query}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    if _opt(args, 'max_funcs'):
        p["max_funcs"] = args.max_funcs
    if _opt(args, 'case_sensitive', False):
        p["case_sensitive"] = True
    r = _rpc_call(args, config, "search_code", p)
    if not r:
        log.debug("cmd_search_code: RPC returned None")
        return
    log.debug("cmd_search_code: found %d functions, scanned %d", r.get("total", 0), r.get("functions_scanned", 0))
    print(f"  Query: \"{r.get('query', '')}\"  Found: {r.get('total', 0)} functions  (scanned: {r.get('functions_scanned', 0)})")
    for entry in r.get("results", []):
        print(f"\n    {entry['addr']}  {entry['name']}")
        for m in entry.get("matches", []):
            print(f"      L{m['line_num']}: {m['text']}")


def cmd_strings_xrefs(ctx: CmdContext):
    """Strings with referencing functions."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_strings_xrefs: filter=%s", _opt(args, 'filter'))
    p = {}
    if _opt(args, 'filter'):
        p["filter"] = args.filter
    if _opt(args, 'max'):
        p["max_results"] = args.max
    if _opt(args, 'min_refs'):
        p["min_refs"] = args.min_refs
    r = _rpc_call(args, config, "strings_xrefs", p)
    if not r:
        log.debug("cmd_strings_xrefs: RPC returned None")
        return
    log.debug("cmd_strings_xrefs: got %d strings with xrefs", r.get("total", 0))
    print(f"  Total: {r.get('total', 0)} strings with xrefs")
    for entry in r.get("results", []):
        val = _truncate(entry['value'], 60)
        print(f"\n    {entry['addr']}  \"{val}\"  ({entry['ref_count']} refs)")
        for ref in entry.get("refs", [])[:5]:
            fn = ref.get("func_name", "")
            print(f"      <- {ref['addr']}  {fn}  [{ref['type']}]")
        if entry['ref_count'] > 5:
            print(f"      ... and {entry['ref_count'] - 5} more")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))


def cmd_func_similarity(ctx: CmdContext):
    """Compare two functions by similarity."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_func_similarity: addr_a=%s addr_b=%s", args.addr_a, args.addr_b)
    p = {"addr_a": args.addr_a, "addr_b": args.addr_b}
    r = _rpc_call(args, config, "func_similarity", p)
    if not r:
        return
    a, b = r["func_a"], r["func_b"]
    sim = r["similarity"]
    print(f"  Function A: {a['name']} ({a['addr']})  size={a['size']}  blocks={a['block_count']}  callees={a['callee_count']}")
    print(f"  Function B: {b['name']} ({b['addr']})  size={b['size']}  blocks={b['block_count']}  callees={b['callee_count']}")
    print(f"\n  Similarity:")
    print(f"    Size ratio:      {sim['size_ratio']:.4f}")
    print(f"    Block ratio:     {sim['block_ratio']:.4f}")
    print(f"    Callee Jaccard:  {sim['callee_jaccard']:.4f}")
    print(f"    Overall:         {sim['overall']:.4f}")
    common = r.get("common_callees", [])
    if common:
        print(f"\n  Common callees ({len(common)}):")
        for c in common[:20]:
            print(f"    {c}")
        if len(common) > 20:
            print(f"    ... and {len(common) - 20} more")


def cmd_data_refs(ctx: CmdContext):
    """Data segment reference analysis."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_data_refs: filter=%s segment=%s", _opt(args, 'filter'), _opt(args, 'segment'))
    p = {}
    if _opt(args, 'filter'):
        p["filter"] = args.filter
    if _opt(args, 'segment'):
        p["segment"] = args.segment
    if _opt(args, 'max'):
        p["max_results"] = args.max
    r = _rpc_call(args, config, "data_refs", p)
    if not r:
        log.debug("cmd_data_refs: RPC returned None")
        return
    log.debug("cmd_data_refs: got %d data references", r.get("total", 0))
    print(f"  Total: {r.get('total', 0)} data references")
    for entry in r.get("results", []):
        print(f"\n    {entry['addr']}  {entry['name']}  [{entry['segment']}]  size={entry['size']}  refs={entry['ref_count']}")
        for ref in entry.get("refs", [])[:5]:
            print(f"      <- {ref['addr']}  {ref.get('func', '')}  [{ref['type']}]")
        if entry['ref_count'] > 5:
            print(f"      ... and {entry['ref_count'] - 5} more")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))


def cmd_basic_blocks(ctx: CmdContext):
    """Basic blocks and CFG for a function."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_basic_blocks: addr=%s", args.addr)
    fmt = _opt(args, 'format', 'mermaid') or 'mermaid'
    p = {"addr": args.addr}
    r = _rpc_call(args, config, "basic_blocks", p)
    if not r:
        log.debug("cmd_basic_blocks: RPC returned None")
        return
    log.debug("cmd_basic_blocks: blocks=%d edges=%d", r.get("block_count", 0), r.get("edge_count", 0))
    graph_only = _opt(args, 'graph_only', False)
    print(f"  Function: {r.get('name', '')} ({r.get('addr', '')})")
    print(f"  Blocks: {r.get('block_count', 0)}, Edges: {r.get('edge_count', 0)}")
    if not graph_only:
        for bb in r.get("blocks", []):
            succs = ", ".join(bb.get("successors", []))
            print(f"    {bb['start']}-{bb['end']}  size={bb['size']}  -> [{succs}]")
    content = r.get("dot" if fmt == "dot" else "mermaid", "")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, content)
    else:
        print()
        print(content)


def cmd_stack_frame(ctx: CmdContext):
    """Show stack frame layout with local variables."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_stack_frame: addr=%s", args.addr)
    r = _rpc_call(args, config, "stack_frame", {"addr": args.addr})
    if not r:
        return
    print(f"  Function: {r.get('name', '')} ({r.get('addr', '')})")
    print(f"  Frame size: {r.get('frame_size', 0)}  (locals={r.get('locals_size', 0)}, "
          f"args={r.get('args_size', 0)}, retaddr={r.get('retaddr_size', 0)})")
    print(f"  Members: {r.get('member_count', 0)}")
    if r.get("members"):
        print()
        print("  | {:>6} | {:>6} | {:<30} | {:<20} | {} |".format(
            "Offset", "Size", "Name", "Type", "Kind"))
        print("  |--------|--------|" + "-" * 32 + "|" + "-" * 22 + "|------|")
        for m in r["members"]:
            print("  | {:>6} | {:>6} | {:<30} | {:<20} | {:<4} |".format(
                m["offset"], m["size"], m["name"],
                _truncate(m.get("type", ""), 20), m["kind"]))


def cmd_switch_table(ctx: CmdContext):
    """Analyze switch/jump tables in a function."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_switch_table: addr=%s", args.addr)
    r = _rpc_call(args, config, "switch_table", {"addr": args.addr})
    if not r:
        log.debug("cmd_switch_table: RPC returned None")
        return
    log.debug("cmd_switch_table: found %d switch tables", r.get("switch_count", 0))
    print(f"  Function: {r.get('name', '')} ({r.get('addr', '')})")
    print(f"  Switch tables: {r.get('switch_count', 0)}")
    for sw in r.get("switches", []):
        default = sw.get("default") or "none"
        print(f"\n    Switch @ {sw['addr']}  ({sw['case_count']} cases, default={default})")
        for case in sw.get("cases", []):
            print(f"      case {case['index']}: -> {case['target']}")
