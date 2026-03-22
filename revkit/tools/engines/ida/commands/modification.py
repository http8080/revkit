"""Modification commands — rename, set_type, comment, patch, search_const, auto_rename, rename_batch."""

import json
import os

from ..core import (
    _rpc_call, _opt, _save_local, _build_params,
    _log_ok, _log_err, _log_info,
    AUTO_GENERATED_PREFIXES,
)
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


def cmd_proxy_rename(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_rename: addr=%s name=%s", args.addr, args.name)
    r = _rpc_call(args, config, "set_name", {"addr": args.addr, "name": args.name})
    if r:
        _log_ok(f"Renamed {r['addr']} -> {r['name']}")


def cmd_proxy_set_type(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_set_type: addr=%s type=%s", args.addr, args.type_str)
    r = _rpc_call(args, config, "set_type", {"addr": args.addr, "type": args.type_str})
    if r:
        _log_ok(f"Type set at {r['addr']}: {r.get('type', '')}")


def cmd_proxy_comment(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_proxy_comment: addr=%s", args.addr)
    p = {"addr": args.addr, "comment": args.text}
    if _opt(args, 'repeatable', False): p["repeatable"] = True
    if _opt(args, 'type'): p["type"] = args.type
    r = _rpc_call(args, config, "set_comment", p)
    if r:
        _log_ok(f"Comment set at {r['addr']}")


def cmd_patch(ctx: CmdContext):
    """Patch bytes at an address."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_patch: addr=%s bytes=%s", args.addr, args.hex_bytes)
    hex_bytes = " ".join(args.hex_bytes)
    p = {"addr": args.addr, "bytes": hex_bytes}
    r = _rpc_call(args, config, "patch_bytes", p)
    if not r:
        log.debug("cmd_patch: RPC returned None")
        return
    log.debug("cmd_patch: patched %d bytes at %s", r.get("size", 0), r.get("addr", "?"))
    print(f"  Address:  {r.get('addr', '')}")
    print(f"  Original: {r.get('original', '')}")
    print(f"  Patched:  {r.get('patched', '')}")
    print(f"  Size:     {r.get('size', 0)} bytes")


def cmd_search_const(ctx: CmdContext):
    """Search for immediate/constant values."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_search_const: value=%s", args.value)
    p = {"value": args.value}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    r = _rpc_call(args, config, "search_const", p)
    if not r:
        log.debug("cmd_search_const: RPC returned None")
        return
    log.debug("cmd_search_const: found %d results", r.get("total", 0))
    lines = [f"  Value: {r.get('value', '')}  Found: {r.get('total', 0)}"]
    for entry in r.get("results", []):
        func = entry.get("func", "")
        func_str = f"  [{func}]" if func else ""
        lines.append(f"    {entry['addr']}  {entry.get('disasm', '')}{func_str}")
    text = "\n".join(lines)
    out = _opt(args, 'out')
    if out:
        _save_local(out, text)
    else:
        print(text)


def cmd_auto_rename(ctx: CmdContext):
    """Heuristic auto-rename sub_ functions."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_auto_rename: apply=%s", _opt(args, 'apply', False))
    dry_run = not _opt(args, 'apply', False)
    max_funcs = _opt(args, 'max_funcs', 200) or 200
    p = {"dry_run": dry_run, "max_funcs": max_funcs}
    r = _rpc_call(args, config, "auto_rename", p)
    if not r:
        log.debug("cmd_auto_rename: RPC returned None")
        return
    log.debug("cmd_auto_rename: %d renames suggested", r.get("total", 0))
    mode = "DRY RUN" if dry_run else "APPLIED"
    print(f"  [{mode}] {r.get('total', 0)} renames suggested")
    for entry in r.get("renames", [])[:50]:
        print(f"    {entry['addr']}  {entry['old_name']} -> {entry['new_name']}")
    if r.get("total", 0) > 50:
        print(f"    ... and {r['total'] - 50} more")
    if dry_run and r.get("total", 0) > 0:
        print(f"\n  Use --apply to actually rename")


def cmd_rename_batch(ctx: CmdContext):
    """Batch rename from CSV/JSON file."""
    args, config = ctx.args, ctx.config
    input_file = args.input_file
    log.debug("cmd_rename_batch: input_file=%s", input_file)
    if not os.path.isfile(input_file):
        _log_err(f"File not found: {input_file}")
        return

    entries = []
    if input_file.endswith(".json"):
        with open(input_file, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict) and "entries" in data:
                entries = data["entries"]
            elif isinstance(data, dict):
                entries = [{"addr": k, "name": v} for k, v in data.items()]
    else:
        # CSV format: addr,name (one per line)
        with open(input_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                if len(parts) == 2:
                    entries.append({"addr": parts[0].strip(), "name": parts[1].strip()})

    if not entries:
        log.warning("cmd_rename_batch: no entries found in %s", input_file)
        _log_err("No rename entries found in file")
        return
    log.debug("cmd_rename_batch: parsed %d entries", len(entries))

    _log_info(f"Renaming {len(entries)} symbols...")
    r = _rpc_call(args, config, "rename_batch", {"entries": entries})
    if not r:
        return
    print(f"  Total: {r.get('total', 0)}, Success: {r.get('success', 0)}, Failed: {r.get('failed', 0)}")
    for entry in r.get("renames", [])[:30]:
        status = "OK" if entry.get("ok") else "FAIL"
        print(f"    [{status}] {entry['addr']}  {entry['name']}")
