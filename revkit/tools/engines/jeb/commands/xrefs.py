"""Xrefs commands -- cross-references, call graph."""

import logging
import os

from ..core import (
    _rpc_call, _opt, _log_ok, _log_err, _log_info, _save_local,
)
from .analysis import _safe_len
from ...base import CmdContext

log = logging.getLogger(__name__)


def cmd_xrefs(ctx: CmdContext):
    """Show cross-references to/from a signature."""
    args, config = ctx.args, ctx.config
    direction = _opt(args, 'direction', 'to')
    sig = args.sig
    log.debug("cmd_xrefs: sig=%s direction=%s", sig, direction)

    _XREF_DIRS = [
        ("to",   "get_xrefs_to",   "TO",   "from_sig", "from_name"),
        ("from", "get_xrefs_from", "FROM", "to_sig",   "to_name"),
    ]
    first = True
    for d, rpc, label, sig_key, name_key in _XREF_DIRS:
        if direction not in (d, "both"):
            continue
        if not first:
            print()
        first = False
        r = _rpc_call(args, config, rpc, {"sig": sig})
        if r:
            log.debug("cmd_xrefs: %s got %d refs", label, r.get('total', 0))
            print(f"Xrefs {label} {sig} ({r.get('total', 0)})")
            for ref in r.get("refs", []):
                # #32: show resolved method name
                method_sig = ref.get('method_sig', '')
                addr = ref.get('address', ref.get(sig_key, ''))
                display = method_sig if method_sig else str(addr)
                ref_type = ref.get('type', '')
                print(f"  {display:<60}  {ref_type}")


def cmd_callers(ctx: CmdContext):
    """Shortcut for xrefs --direction to (who calls this)."""
    args, config = ctx.args, ctx.config
    args.direction = "to"
    cmd_xrefs(ctx)


def cmd_callees(ctx: CmdContext):
    """Shortcut for xrefs --direction from (what this calls)."""
    args, config = ctx.args, ctx.config
    args.direction = "from"
    cmd_xrefs(ctx)


def _print_graph(r, args, extra_info=None):
    """Shared output for callgraph / cross-refs results."""
    fmt = _opt(args, 'format', 'mermaid') or 'mermaid'
    print(f"  Root: {r.get('root', '')}")
    if extra_info:
        print(extra_info)
    print(f"  Nodes: {_safe_len(r.get('nodes', []))}, "
          f"Edges: {_safe_len(r.get('edges', []))}")

    # #34: svg/png via graphviz dot
    if fmt in ("svg", "png"):
        dot_content = r.get("dot", "")
        if not dot_content:
            _log_err("No DOT output available for image generation")
            return
        out_path = _opt(args, 'out') or f"callgraph.{fmt}"
        _render_dot_image(dot_content, fmt, out_path)
        return

    content = r.get("dot" if fmt == "dot" else "mermaid", "")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, content)
    else:
        print()
        print(content)


def _render_dot_image(dot_content, fmt, out_path):
    """#34: Render DOT to SVG/PNG using graphviz dot command."""
    import subprocess as sp
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.dot', delete=False) as f:
            f.write(dot_content)
            dot_path = f.name
        sp.check_call(["dot", f"-T{fmt}", "-o", out_path, dot_path], timeout=30)
        os.remove(dot_path)
        _log_ok(f"Saved {fmt.upper()}: {out_path}")
    except FileNotFoundError:
        _log_err("graphviz 'dot' not found. Install graphviz: https://graphviz.org/download/")
        # Fallback: save DOT file
        fallback = out_path.rsplit('.', 1)[0] + '.dot'
        _save_local(fallback, dot_content)
        _log_info(f"DOT file saved instead: {fallback}")
    except Exception as e:
        _log_err(f"dot render failed: {e}")


def cmd_callgraph(ctx: CmdContext):
    """Generate function/method call graph."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_callgraph: sig=%s depth=%s direction=%s",
              args.class_sig, _opt(args, 'depth', 3), _opt(args, 'direction', 'callees'))
    fmt = _opt(args, 'format', 'mermaid')
    p = {"sig": args.class_sig,
         "depth": _opt(args, 'depth', 3),
         "direction": _opt(args, 'direction', 'callees')}
    # #33: exclude pattern
    exclude = _opt(args, 'exclude')
    if exclude:
        p["exclude"] = exclude
    # #34: svg/png need dot format from server
    if fmt in ("svg", "png"):
        p["format"] = "dot"
    r = _rpc_call(args, config, "callgraph", p)
    if r:
        _print_graph(r, args)


def cmd_cross_refs(ctx: CmdContext):
    """Multi-level xref chain tracing."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_cross_refs: sig=%s depth=%s direction=%s",
              args.sig, _opt(args, 'depth', 3), _opt(args, 'direction', 'to'))
    p = {
        "sig": args.sig,
        "depth": _opt(args, 'depth', 3),
        "direction": _opt(args, 'direction', 'to'),
    }
    r = _rpc_call(args, config, "cross_refs", p)
    if not r:
        log.warning("cmd_cross_refs: RPC returned None")
        return
    log.debug("cmd_cross_refs: %d chain entries", len(r.get('chain', [])))
    for entry in r.get("chain", []):
        indent = "  " * entry.get("depth", entry.get("level", 0))
        print(f"    {indent}{entry.get('from', '')} -> {entry.get('to', '')}  [{entry.get('type', '')}]")
    _print_graph(r, args,
                 f"  Depth: {r.get('depth')}  Direction: {r.get('direction')}")
