# -*- coding: utf-8 -*-
"""Graph handlers -- xrefs, callgraph, cross-refs.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

from .helpers import (
    _raise_not_found, _require_class, _resolve_dex_item,
    _EdgeCollector, _graph_result,
)

_VALID_DIRECTIONS = frozenset(("to", "from", "both"))


def _handle_get_xrefs(self, params):
    """Cross-references for an item (class, method, or field).

    direction="to" (default): who references this item.
    direction="from": what this item references.
    """
    item_sig = params.get("item_sig")
    direction = params.get("direction", "to")
    if direction not in _VALID_DIRECTIONS:
        raise self.RpcError("INVALID_PARAM",
                            "direction must be one of: to, from, both",
                            "Use --direction to|from|both")
    dex = self._find_dex_for_any(item_sig)
    if not dex:
        _raise_not_found(self, "item", item_sig)

    # Resolve item and pool type
    item, pool_type = _resolve_dex_item(dex, item_sig)
    if not item:
        _raise_not_found(self, "item", item_sig)

    idx = item.getIndex()
    refs = []

    if direction == "from":
        refmgr = dex.getReferenceManager()
        if refmgr:
            ref_map = refmgr.getReferences(pool_type, idx)
            if ref_map:
                for e in ref_map.entrySet():
                    ref_pool = e.getKey()
                    ref_indices = e.getValue()
                    for ref_idx in ref_indices:
                        ref_entry = {
                            "address": "%s#%d" % (str(ref_pool), ref_idx),
                            "pool_type": str(ref_pool),
                            "index": ref_idx,
                            "type": "REFERENCE",
                        }
                        # Resolve target name
                        target = dex.getMethod(ref_idx)
                        if target:
                            ref_entry["method_sig"] = target.getSignature(True)
                            ref_entry["method_name"] = target.getName(True)
                        else:
                            target = dex.getClass(ref_idx)
                            if target:
                                ref_entry["class_sig"] = target.getSignature(True)
                        refs.append(ref_entry)
    else:
        # "to" direction (default): who references this item
        xref_addrs = dex.getCrossReferences(pool_type, idx)
        if xref_addrs:
            for addr in xref_addrs:
                ref_entry = {
                    "address": addr.getInternalAddress(),
                    "user_address": addr.getUserAddress(),
                    "type": str(addr.getReferenceType()),
                }
                # Resolve caller method name from internal address
                internal = str(addr.getInternalAddress())
                plus_pos = internal.rfind("+")
                method_part = internal[:plus_pos] if plus_pos > 0 else internal
                m = dex.getMethod(method_part)
                if m:
                    ref_entry["method_sig"] = m.getSignature(True)
                    ref_entry["method_name"] = m.getName(True)
                refs.append(ref_entry)

    return {"item_sig": item_sig, "direction": direction,
            "total": len(refs), "refs": refs}


def _handle_callgraph(self, params):
    """Call graph for a class (mermaid/DOT output).

    Explores method-level call relationships starting from a class.
    """
    from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

    class_sig = params.get("class_sig")
    depth = min(params.get("depth", 2), 5)
    direction = params.get("direction", "both")  # callers, callees, both
    # Exclude pattern (comma-separated prefixes)
    exclude_raw = params.get("exclude", "")
    exclude_prefixes = [e.strip() for e in exclude_raw.split(",") if e.strip()] if exclude_raw else []

    dex, cls = _require_class(self, class_sig)

    nodes = set()
    ec = _EdgeCollector()
    visited = set()

    # Collect initial method sigs from the class
    current_sigs = []
    for m in cls.getMethods():
        sig = m.getSignature(True)
        current_sigs.append(sig)
        nodes.add(sig)

    refmgr = dex.getReferenceManager()
    for _level in range(depth):
        if not current_sigs:
            break
        next_sigs = []
        for sig in current_sigs:
            if sig in visited:
                continue
            visited.add(sig)

            item = dex.getMethod(sig)
            if not item:
                continue
            idx = item.getIndex()

            # Callees (from)
            if direction in ("callees", "both") and refmgr:
                try:
                    ref_map = refmgr.getReferences(DexPoolType.METHOD, idx)
                    if ref_map:
                        for e in ref_map.entrySet():
                            if str(e.getKey()) != str(DexPoolType.METHOD):
                                continue
                            for ref_idx in e.getValue():
                                target = dex.getMethod(ref_idx)
                                if target:
                                    t_sig = target.getSignature(True)
                                    # Exclude filter
                                    if exclude_prefixes and any(t_sig.startswith("L" + p.replace(".", "/")) for p in exclude_prefixes):
                                        continue
                                    nodes.add(t_sig)
                                    ec.add(sig, t_sig)
                                    next_sigs.append(t_sig)
                except Exception:
                    pass

            # Callers (to)
            if direction in ("callers", "both"):
                xref_addrs = dex.getCrossReferences(DexPoolType.METHOD, idx)
                if xref_addrs:
                    for addr in xref_addrs:
                        caller_addr = addr.getInternalAddress()
                        caller_str = str(caller_addr) if caller_addr else ""
                        # Exclude filter
                        if exclude_prefixes and any(caller_str.startswith("L" + p.replace(".", "/")) for p in exclude_prefixes):
                            continue
                        nodes.add(caller_addr)
                        ec.add(caller_addr, sig)
                        next_sigs.append(caller_addr)

        current_sigs = next_sigs

    return _graph_result(self, params, class_sig, nodes, ec, "callgraph")


def _handle_cross_refs(self, params):
    """Multi-level xref chain tracing.

    Starting from item_sig, follows xrefs up to 'depth' levels.
    """
    item_sig = params.get("item_sig")
    depth = min(params.get("depth", 2), 5)
    direction = params.get("direction", "to")
    if direction not in _VALID_DIRECTIONS:
        raise self.RpcError("INVALID_PARAM",
                            "direction must be one of: to, from, both",
                            "Use --direction to|from|both")

    dex = self._find_dex_for_any(item_sig)
    if not dex:
        _raise_not_found(self, "item", item_sig)

    nodes = set()
    nodes.add(item_sig)
    ec = _EdgeCollector()
    chain = []
    visited = set()
    current_sigs = [item_sig]

    for level in range(depth):
        if not current_sigs:
            break
        next_sigs = []
        for sig in current_sigs:
            if sig in visited:
                continue
            visited.add(sig)

            item, pool_type = _resolve_dex_item(dex, sig)
            if not item:
                continue
            idx = item.getIndex()

            if direction in ("to", "both"):
                xref_addrs = dex.getCrossReferences(pool_type, idx)
                if xref_addrs:
                    for addr in xref_addrs:
                        ref_addr = addr.getInternalAddress()
                        # Resolve to full method signature
                        resolved = str(ref_addr)
                        plus_pos = resolved.rfind("+")
                        method_part = resolved[:plus_pos] if plus_pos > 0 else resolved
                        m = dex.getMethod(method_part)
                        display_addr = m.getSignature(True) if m else ref_addr
                        nodes.add(display_addr)
                        ec.add(display_addr, sig)
                        chain.append({
                            "depth": level + 1,
                            "from": display_addr,
                            "to": sig,
                            "type": str(addr.getReferenceType()),
                        })
                        next_sigs.append(method_part if m else str(ref_addr))

            if direction in ("from", "both"):
                refmgr = dex.getReferenceManager()
                if refmgr:
                    try:
                        ref_map = refmgr.getReferences(pool_type, idx)
                        if ref_map:
                            for e in ref_map.entrySet():
                                for ref_idx in e.getValue():
                                    # Resolve to full signature
                                    target = dex.getMethod(ref_idx)
                                    if target:
                                        display_addr = target.getSignature(True)
                                    else:
                                        display_addr = "%s#%d" % (str(e.getKey()), ref_idx)
                                    nodes.add(display_addr)
                                    ec.add(sig, display_addr)
                                    chain.append({
                                        "depth": level + 1,
                                        "from": sig,
                                        "to": display_addr,
                                        "type": "REFERENCE",
                                    })
                                    next_sigs.append(display_addr)
                    except Exception:
                        pass

        current_sigs = next_sigs

    result = _graph_result(self, params, item_sig, nodes, ec, "cross_refs")
    result["depth"] = depth
    result["chain"] = chain
    return result
