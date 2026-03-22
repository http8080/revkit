"""Graph API — call graph, cross refs, basic blocks / CFG."""

from ..framework import (
    _fmt_addr, _resolve_addr, _clamp_int, _require_function,
    _save_output, _xref_type_str,
)


def _generate_dot_graph(nodes, edges, root_addr):
    """Generate DOT format graph."""
    lines = ["digraph callgraph {", '  rankdir=LR;',
             '  node [shape=box, style=filled, fillcolor="#f0f0f0"];']
    for addr, name in nodes.items():
        color = '#ffcccc' if addr == root_addr else '#f0f0f0'
        label = name.replace('"', '\\"')
        lines.append(f'  "{addr}" [label="{label}", fillcolor="{color}"];')
    for src, dst in edges:
        lines.append(f'  "{src}" -> "{dst}";')
    lines.append("}")
    return "\n".join(lines)


def _generate_mermaid_graph(nodes, edges):
    """Generate Mermaid format graph."""
    lines = ["graph LR"]
    for addr, name in nodes.items():
        safe = name.replace('"', "'")
        lines.append(f'  {addr.replace("0x", "x")}["{safe}"]')
    for src, dst in edges:
        lines.append(f'  {src.replace("0x", "x")} --> {dst.replace("0x", "x")}')
    return "\n".join(lines)


def _collect_call_graph(start_ea, depth, direction, nodes, edges):
    """Recursively collect call graph nodes and edges."""
    import idc, ida_funcs, idautils

    def _walk(ea, cur_depth):
        if cur_depth > depth:
            return
        addr_str = _fmt_addr(ea)
        if addr_str in nodes:
            return
        nodes[addr_str] = idc.get_func_name(ea) or addr_str
        if direction == "callees":
            func = ida_funcs.get_func(ea)
            if not func:
                return
            seen = set()
            for item_ea in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item_ea):
                    target = ida_funcs.get_func(xref.to)
                    if target and target.start_ea != func.start_ea and target.start_ea not in seen:
                        seen.add(target.start_ea)
                        t_addr = _fmt_addr(target.start_ea)
                        edges.append((addr_str, t_addr))
                        _walk(target.start_ea, cur_depth + 1)
        else:  # callers
            for xref in idautils.XrefsTo(ea):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func and caller_func.start_ea != ea:
                    c_addr = _fmt_addr(caller_func.start_ea)
                    edges.append((c_addr, addr_str))
                    _walk(caller_func.start_ea, cur_depth + 1)

    _walk(start_ea, 0)


def _handle_callgraph(params):
    """Build call graph starting from a function."""
    ea = _resolve_addr(params.get("addr"))
    depth = _clamp_int(params, "depth", 3, 10)
    direction = params.get("direction", "callees")

    nodes = {}
    edges = []

    if direction in ("callees", "both"):
        _collect_call_graph(ea, depth, "callees", nodes, edges)
    if direction in ("callers", "both"):
        _collect_call_graph(ea, depth, "callers", nodes, edges)

    edges = list(dict.fromkeys(edges))

    root_addr = _fmt_addr(ea)
    dot = _generate_dot_graph(nodes, edges, root_addr)
    mermaid = _generate_mermaid_graph(nodes, edges)
    saved_to = _save_output(params.get("output"), dot)
    return {
        "root": root_addr,
        "root_name": nodes.get(root_addr, ""),
        "nodes": len(nodes),
        "edges": len(edges),
        "dot": dot,
        "mermaid": mermaid,
        "saved_to": saved_to,
        "hint": "nodes/edges are counts (int), not lists. Use dot/mermaid for graph data.",
    }


def _handle_cross_refs(params):
    """Trace xref chains N levels deep from an address."""
    import idautils, idc, ida_funcs
    ea = _resolve_addr(params.get("addr"))
    depth = _clamp_int(params, "depth", 3, 10)
    direction = params.get("direction", "to")

    nodes = {}
    edges = []

    def _walk(cur_ea, cur_depth, dir_):
        addr_str = _fmt_addr(cur_ea)
        if addr_str in nodes:
            return
        name = idc.get_func_name(cur_ea) or idc.get_name(cur_ea) or addr_str
        nodes[addr_str] = {"name": name, "level": cur_depth}
        if cur_depth >= depth:
            return
        if dir_ in ("to", "both"):
            for xref in idautils.XrefsTo(cur_ea):
                src = _fmt_addr(xref.frm)
                edges.append((src, addr_str, _xref_type_str(xref.type)))
                func = ida_funcs.get_func(xref.frm)
                target = func.start_ea if func else xref.frm
                _walk(target, cur_depth + 1, dir_)
        if dir_ in ("from", "both"):
            for xref in idautils.XrefsFrom(cur_ea):
                dst = _fmt_addr(xref.to)
                edges.append((addr_str, dst, _xref_type_str(xref.type)))
                func = ida_funcs.get_func(xref.to)
                target = func.start_ea if func else xref.to
                _walk(target, cur_depth + 1, dir_)

    _walk(ea, 0, direction)
    graph_nodes = {a: info["name"] for a, info in nodes.items()}
    graph_edges = [(src, dst) for src, dst, _ in edges]
    mermaid = _generate_mermaid_graph(graph_nodes, graph_edges)
    dot = _generate_dot_graph(graph_nodes, graph_edges, _fmt_addr(ea))
    chain = [{"addr": a, "name": info["name"], "level": info["level"]}
             for a, info in sorted(nodes.items(), key=lambda x: x[1]["level"])]
    saved_to = _save_output(params.get("output"), mermaid)
    return {
        "root": _fmt_addr(ea), "depth": depth, "direction": direction,
        "nodes": len(nodes), "edges": len(edges),
        "chain": chain,
        "edge_details": [{"from": s, "to": d, "type": t} for s, d, t in edges],
        "mermaid": mermaid, "dot": dot, "saved_to": saved_to,
        "hint": "nodes/edges are counts (int). Use chain/edge_details for structured data.",
    }


def _handle_basic_blocks(params):
    """Get basic blocks and CFG for a function."""
    import ida_gdl, idc
    ea = _resolve_addr(params.get("addr"))
    func = _require_function(ea)

    fc = ida_gdl.FlowChart(func)
    blocks = []
    nodes = {}
    edges = []

    for bb in fc:
        addr_str = _fmt_addr(bb.start_ea)
        end_str = _fmt_addr(bb.end_ea)
        size = bb.end_ea - bb.start_ea
        first_insn = idc.generate_disasm_line(bb.start_ea, 0) or ""
        last_ea = idc.prev_head(bb.end_ea, bb.start_ea)
        last_insn = idc.generate_disasm_line(last_ea, 0) if last_ea != idc.BADADDR else ""

        safe_insn = first_insn.replace('"', "'")
        nodes[addr_str] = f"{addr_str}\\n{safe_insn}"

        succs = []
        for succ in bb.succs():
            succ_addr = _fmt_addr(succ.start_ea)
            succs.append(succ_addr)
            edges.append((addr_str, succ_addr))

        preds = []
        for pred in bb.preds():
            preds.append(_fmt_addr(pred.start_ea))

        blocks.append({
            "start": addr_str, "end": end_str, "size": size,
            "first_insn": first_insn, "last_insn": last_insn or "",
            "successors": succs, "predecessors": preds,
        })

    func_name = idc.get_func_name(func.start_ea) or ""
    root_addr = _fmt_addr(func.start_ea)
    mermaid = _generate_mermaid_graph(nodes, edges)
    dot = _generate_dot_graph(nodes, edges, root_addr)
    saved_to = _save_output(params.get("output"), mermaid)
    return {
        "addr": root_addr, "name": func_name,
        "block_count": len(blocks), "edge_count": len(edges),
        "blocks": blocks,
        "mermaid": mermaid, "dot": dot, "saved_to": saved_to,
        "hint": "block_count/edge_count are counts (int). Use blocks array for structured data.",
    }
