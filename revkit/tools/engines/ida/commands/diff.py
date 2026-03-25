"""Diff commands — diff, compare, code-diff between instances."""

import json
import os
import time

from ..core import (
    post_rpc, load_registry,
    _opt, _log_ok, _log_err, _log_info, _log_warn,
    _save_local, _make_args, _format_arch_info,
    make_instance_id, get_idb_path,
)


def _print_truncated(items, formatter=None, limit=50):
    """Print a list of items with optional formatter, truncating after limit."""
    if isinstance(items, str):
        lines = items.splitlines()
        for line in lines[:limit]:
            print(line)
        if len(lines) > limit:
            print(f"\n... ({len(lines) - limit} more lines)")
        return
    for item in items[:limit]:
        line = formatter(item) if formatter else str(item)
        print(f"    {line}")
    if len(items) > limit:
        print(f"    ... and {len(items) - limit} more")
from ..core import arch_detect
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


def _resolve_by_hint(hint, registry):
    """Resolve instance by ID or binary name hint. Shared by diff/code-diff."""
    if hint in registry:
        return hint, registry[hint]
    matches = [(k, v) for k, v in registry.items()
               if hint.lower() in v.get("binary", "").lower()]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        _log_err(f"No instance matching '{hint}'")
    else:
        _log_err(f"Multiple instances match '{hint}':")
        for k, v in matches:
            print(f"  {k}  {v.get('binary', '?')}")
    return None, None


def _get_func_map(config, iid, info, count=10000):
    """Get {name: func_dict} from an instance. Shared by diff/compare/code-diff."""
    port = info.get("port")
    if not port:
        _log_err(f"Instance {iid} has no port")
        return None
    resp = post_rpc(config, port, "get_functions", iid, {"count": count})
    if "error" in resp:
        _log_err(f"{iid}: {resp['error'].get('message')}")
        return None
    return {f["name"]: f for f in resp.get("result", {}).get("data", [])}


def cmd_diff(ctx: CmdContext):
    """Compare functions between two instances."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_diff: instance_a=%s instance_b=%s", args.instance_a, args.instance_b)
    registry = load_registry()

    iid_a, info_a = _resolve_by_hint(args.instance_a, registry)
    if not iid_a: return
    iid_b, info_b = _resolve_by_hint(args.instance_b, registry)
    if not iid_b: return

    funcs_a = _get_func_map(config, iid_a, info_a)
    funcs_b = _get_func_map(config, iid_b, info_b)
    if funcs_a is None or funcs_b is None:
        log.warning("cmd_diff: could not get function maps")
        return

    log.debug("cmd_diff: A has %d funcs, B has %d funcs", len(funcs_a), len(funcs_b))
    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())
    only_a = names_a - names_b
    only_b = names_b - names_a
    common = names_a & names_b
    size_diff = []
    for name in common:
        sa = funcs_a[name].get("size", 0)
        sb = funcs_b[name].get("size", 0)
        if sa != sb:
            size_diff.append((name, funcs_a[name]["addr"], sa, funcs_b[name]["addr"], sb))

    bin_a = info_a.get("binary", "?")
    bin_b = info_b.get("binary", "?")
    print(f"  Comparing: {bin_a} ({iid_a}) vs {bin_b} ({iid_b})")
    print(f"  Functions: {len(names_a)} vs {len(names_b)}")
    print(f"  Common: {len(common)}, Only in A: {len(only_a)}, Only in B: {len(only_b)}, Size changed: {len(size_diff)}")

    if only_a:
        print(f"\n  Only in {bin_a}:")
        _print_truncated(sorted(only_a), lambda n: f"{funcs_a[n]['addr']}  {n}")

    if only_b:
        print(f"\n  Only in {bin_b}:")
        _print_truncated(sorted(only_b), lambda n: f"{funcs_b[n]['addr']}  {n}")

    if size_diff:
        size_diff.sort(key=lambda x: abs(x[4] - x[2]), reverse=True)
        print(f"\n  Size changed ({len(size_diff)}):")
        def _fmt_sd(t):
            name, addr_a, sa, _, sb = t
            delta = sb - sa
            sign = "+" if delta > 0 else ""
            return f"{addr_a}  {name:<40}  {sa} -> {sb} ({sign}{delta})"
        _print_truncated(size_diff, _fmt_sd)


def _compare_func_maps(funcs_a, funcs_b):
    """Compare two function maps. Returns (added, removed, modified, identical)."""
    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())
    added = names_b - names_a
    removed = names_a - names_b
    common = names_a & names_b
    modified = []
    identical = 0
    for name in common:
        sa = funcs_a[name].get("size", 0)
        sb = funcs_b[name].get("size", 0)
        if sa != sb:
            modified.append((name, funcs_a[name]["addr"], sa, funcs_b[name]["addr"], sb))
        else:
            identical += 1
    modified.sort(key=lambda x: abs(x[4] - x[2]), reverse=True)
    return added, removed, modified, identical


def _display_diff_results(name_a, name_b, funcs_a, funcs_b,
                          added, removed, modified, identical, limit=50):
    """Display patch diff results."""
    print(f"\n  === Patch Diff: {name_a} vs {name_b} ===")
    print(f"  Functions: {len(funcs_a)} vs {len(funcs_b)}")
    print(f"  Identical: {identical}")
    print(f"  Modified:  {len(modified)}")
    print(f"  Added:     {len(added)}")
    print(f"  Removed:   {len(removed)}")

    if modified:
        print(f"\n  Modified functions ({len(modified)}):")
        for name, addr_a, sa, addr_b, sb in modified[:limit]:
            delta = sb - sa
            sign = "+" if delta > 0 else ""
            print(f"    {name:<50}  {sa} -> {sb} ({sign}{delta})")
        if len(modified) > limit:
            print(f"    ... and {len(modified) - limit} more")

    for label, names, funcs in [("Added", added, funcs_b), ("Removed", removed, funcs_a)]:
        if names:
            print(f"\n  {label} functions ({len(names)}):")
            _print_truncated(sorted(names), lambda n: f"{funcs[n]['addr']}  {n}")


def cmd_compare(ctx: CmdContext):
    """Compare two versions of a binary (patch diffing)."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    log.debug("cmd_compare: binary_a=%s binary_b=%s", args.binary_a, args.binary_b)
    from .instance import cmd_start, cmd_wait

    binary_a = os.path.normcase(os.path.abspath(args.binary_a))
    binary_b = os.path.normcase(os.path.abspath(args.binary_b))
    for path in (binary_a, binary_b):
        if not os.path.isfile(path):
            _log_err(f"File not found: {path}")
            return

    idb_dir = _opt(args, 'idb_dir') or os.environ.get("IDA_IDB_DIR") or "."

    _log_info("Starting instances...")
    cfg = _opt(args, 'config')
    for binary in (binary_a, binary_b):
        sa = _make_args(binary=binary, idb_dir=idb_dir, fresh=False, force=True, config=cfg)
        start_ctx = CmdContext(args=sa, config=config, config_path=config_path)
        cmd_start(start_ctx)

    registry = load_registry()
    instances = {}
    for iid, info in registry.items():
        reg_path = os.path.normcase(os.path.abspath(info.get("path", info.get("binary", ""))))
        if reg_path in (binary_a, binary_b) and info.get("state") in ("analyzing", "ready"):
            instances[reg_path] = (iid, info)

    if binary_a not in instances or binary_b not in instances:
        _log_err("Could not start both instances")
        return

    _log_info("Waiting for analysis...")
    for path_key in (binary_a, binary_b):
        iid, info = instances[path_key]
        wait_ctx = CmdContext(args=_make_args(id=iid, timeout=300), config=config, config_path=config_path)
        cmd_wait(wait_ctx)

    ia = instances[binary_a]
    ib = instances[binary_b]
    funcs_a = _get_func_map(config, ia[0], ia[1])
    funcs_b = _get_func_map(config, ib[0], ib[1])
    if not funcs_a or not funcs_b:
        log.warning("cmd_compare: could not get function lists from instances")
        _log_err("Could not get function lists")
        return

    log.debug("cmd_compare: A has %d funcs, B has %d funcs", len(funcs_a), len(funcs_b))
    added, removed, modified, identical = _compare_func_maps(funcs_a, funcs_b)
    _display_diff_results(os.path.basename(binary_a), os.path.basename(binary_b),
                          funcs_a, funcs_b, added, removed, modified, identical)

    log.debug("cmd_compare: identical=%d modified=%d added=%d removed=%d", identical, len(modified), len(added), len(removed))
    out_path = _opt(args, 'out')
    if out_path:
        report = {
            "binary_a": binary_a, "binary_b": binary_b,
            "functions_a": len(funcs_a), "functions_b": len(funcs_b),
            "identical": identical,
            "modified": [{"name": n, "size_a": sa, "size_b": sb} for n, _, sa, _, sb in modified],
            "added": sorted(added),
            "removed": sorted(removed),
        }
        _save_local(out_path, json.dumps(report, ensure_ascii=False, indent=2))


def _compute_code_diffs(config, func_names, port_a, port_b, iid_a, iid_b, bin_a, bin_b):
    """Decompile and diff each function, return list of diffs.
    Optimization: batch decompile all functions per instance (2 RPCs instead of 2N)."""
    import difflib
    if not func_names:
        return []

    # Batch decompile: 2 RPC calls total instead of 2N
    resp_a = post_rpc(config, port_a, "decompile_batch", iid_a, {"addrs": list(func_names)})
    resp_b = post_rpc(config, port_b, "decompile_batch", iid_b, {"addrs": list(func_names)})

    # Index results by function name for O(1) lookup
    def _index_batch(resp):
        results = resp.get("result", {}).get("results", [])
        by_name = {}
        for r in results:
            name = r.get("name", "")
            if name and "code" in r:
                by_name[name] = r["code"]
        return by_name

    codes_a = _index_batch(resp_a) if "error" not in resp_a else {}
    codes_b = _index_batch(resp_b) if "error" not in resp_b else {}

    all_diffs = []
    for name in func_names:
        code_a = codes_a.get(name)
        code_b = codes_b.get(name)
        if code_a is None or code_b is None:
            _log_err(f"Cannot decompile: {name}")
            continue
        if isinstance(code_a, list):
            code_a = "\n".join(code_a)
        if isinstance(code_b, list):
            code_b = "\n".join(code_b)
        if code_a == code_b:
            continue
        diff = list(difflib.unified_diff(
            code_a.splitlines(), code_b.splitlines(),
            fromfile=f"{bin_a}:{name}", tofile=f"{bin_b}:{name}", lineterm="",
        ))
        if diff:
            all_diffs.append({"name": name, "diff": diff})
            print(f"\n  === {name} ===")
            for line in diff:
                print(f"  {line}")
    return all_diffs


def cmd_code_diff(ctx: CmdContext):
    """Compare decompiled code of same-named functions between two instances."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_code_diff: instance_a=%s instance_b=%s", args.instance_a, args.instance_b)

    id_a = args.instance_a
    id_b = args.instance_b
    func_names = _opt(args, 'functions') or []

    registry = load_registry()

    iid_a, info_a = _resolve_by_hint(id_a, registry)
    if not iid_a:
        return
    iid_b, info_b = _resolve_by_hint(id_b, registry)
    if not iid_b:
        return

    port_a = info_a.get("port")
    port_b = info_b.get("port")
    if not port_a or not port_b:
        _log_err("One or both instances have no port (not ready?). Use 'wait <id>' first.")
        return

    if not func_names:
        # Get common functions, find size-changed ones
        resp_a = post_rpc(config, port_a, "get_functions", iid_a, {"count": 10000})
        resp_b = post_rpc(config, port_b, "get_functions", iid_b, {"count": 10000})
        if "error" in resp_a or "error" in resp_b:
            _log_err("Cannot get function lists")
            return
        funcs_a = {f["name"]: f for f in resp_a.get("result", {}).get("data", [])}
        funcs_b = {f["name"]: f for f in resp_b.get("result", {}).get("data", [])}
        common = set(funcs_a.keys()) & set(funcs_b.keys())
        changed = []
        for name in common:
            if funcs_a[name].get("size", 0) != funcs_b[name].get("size", 0):
                changed.append(name)
        changed.sort()
        func_names = changed[:10]
        print(f"  Auto-selected {len(func_names)} size-changed functions from {len(changed)} total")

    out_path = _opt(args, 'out')
    all_diffs = []
    bin_a = os.path.basename(info_a.get("binary", "?"))
    bin_b = os.path.basename(info_b.get("binary", "?"))

    all_diffs = _compute_code_diffs(
        config, func_names, port_a, port_b, iid_a, iid_b, bin_a, bin_b)

    log.debug("cmd_code_diff: got %d diffs", len(all_diffs))
    if not all_diffs:
        print("  No code differences found")

    if out_path and all_diffs:
        content = []
        for d in all_diffs:
            content.append(f"=== {d['name']} ===")
            content.extend(d["diff"])
            content.append("")
        _save_local(out_path, "\n".join(content))
