"""Report commands -- annotations, snapshots, report generation."""

import json
import logging
import os

from ..core import (
    _rpc_call, _opt, _log_ok, _log_err, _log_info,
    _save_local,
)
from .analysis import _safe_len
from .recon import _extract_pkg_activity
from ...base import CmdContext

log = logging.getLogger(__name__)


def _dispatch_subcommand(args, config, action_map):
    """Generic subcommand dispatcher."""
    action = _opt(args, 'action')
    handler = action_map.get(action)
    if handler:
        handler(args, config)
    else:
        _log_err("Specify action: %s" % " or ".join(action_map.keys()))


def cmd_annotations_export(ctx: CmdContext):
    """Export all analysis annotations to a JSON file."""
    args, config = ctx.args, ctx.config
    out_path = _opt(args, 'out') or "annotations.json"
    log.debug("cmd_annotations_export: out=%s", out_path)
    r = _rpc_call(args, config, "export_annotations")
    if not r:
        log.warning("cmd_annotations_export: RPC returned None")
        return
    log.debug("cmd_annotations_export: names=%d comments=%d types=%d",
              _safe_len(r.get('names', 0)), _safe_len(r.get('comments', 0)), _safe_len(r.get('types', 0)))
    _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))
    print(f"  Names: {_safe_len(r.get('names', 0))}, "
          f"Comments: {_safe_len(r.get('comments', 0))}, "
          f"Types: {_safe_len(r.get('types', 0))}")


def cmd_annotations_import(ctx: CmdContext):
    """Import annotations from a JSON file."""
    args, config = ctx.args, ctx.config
    in_path = args.file
    log.debug("cmd_annotations_import: file=%s", in_path)
    if not os.path.isfile(in_path):
        _log_err(f"File not found: {in_path}")
        return
    with open(in_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    r = _rpc_call(args, config, "import_annotations", {"data": data})
    if not r:
        return
    print(f"  Applied - Names: {r.get('names', 0)}, Comments: {r.get('comments', 0)}, Types: {r.get('types', 0)}")
    if r.get("errors"):
        print(f"  Errors: {r['errors']}")


def cmd_annotations(ctx: CmdContext):
    """Dispatch annotations export/import subcommands."""
    args, config = ctx.args, ctx.config
    _dispatch_subcommand(args, config, {
        "export": lambda a, c: cmd_annotations_export(CmdContext(args=a, config=c, config_path=ctx.config_path)),
        "import": lambda a, c: cmd_annotations_import(CmdContext(args=a, config=c, config_path=ctx.config_path)),
    })


def cmd_snapshot_save(ctx: CmdContext):
    """Save a project snapshot."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_snapshot_save: description=%s", _opt(args, 'description', 'Snapshot'))
    desc = _opt(args, 'description', 'Snapshot') or 'Snapshot'
    r = _rpc_call(args, config, "snapshot_save", {"description": desc})
    if not r:
        log.warning("cmd_snapshot_save: RPC returned None")
        return
    log.debug("cmd_snapshot_save: saved %s", r.get('filename', ''))
    _log_ok(f"Snapshot saved: {r.get('filename', '')}")
    if r.get("description"):
        print(f"    Description: {r['description']}")


def cmd_snapshot_list(ctx: CmdContext):
    """List available project snapshots."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_snapshot_list: requesting snapshots")
    r = _rpc_call(args, config, "snapshot_list")
    if not r:
        return
    snapshots = r.get("snapshots", [])
    if not snapshots:
        print("  No snapshots found")
        return
    print(f"  Snapshots ({r.get('total', 0)}):")
    for s in snapshots:
        size_mb = s.get("size", 0) / (1024 * 1024)
        desc = f'  "{s["description"]}"' if s.get("description") else ""
        print(f"    {s.get('created', '')}  {size_mb:.1f}MB  {s.get('filename', '')}{desc}")


def cmd_snapshot_restore(ctx: CmdContext):
    """Restore a project from a snapshot."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_snapshot_restore: filename=%s", args.filename)
    r = _rpc_call(args, config, "snapshot_restore", {"filename": args.filename})
    if not r:
        return
    _log_ok(f"Restored from: {r.get('restored_from', '')}")
    if r.get("backup_of_current"):
        print(f"    Current backed up to: {r['backup_of_current']}")
    if r.get("note"):
        print(f"    Note: {r['note']}")


def cmd_snapshot(ctx: CmdContext):
    """Dispatch snapshot save/list/restore subcommands."""
    args, config = ctx.args, ctx.config
    _dispatch_subcommand(args, config, {
        "save": lambda a, c: cmd_snapshot_save(CmdContext(args=a, config=c, config_path=ctx.config_path)),
        "list": lambda a, c: cmd_snapshot_list(CmdContext(args=a, config=c, config_path=ctx.config_path)),
        "restore": lambda a, c: cmd_snapshot_restore(CmdContext(args=a, config=c, config_path=ctx.config_path)),
    })


def cmd_report(ctx: CmdContext):
    """Generate a markdown analysis report."""
    args, config = ctx.args, ctx.config
    out_path = args.out
    log.debug("cmd_report: out=%s decompile_sigs=%d", out_path, len(_opt(args, 'decompile', []) or []))
    decompile_sigs = _opt(args, 'decompile', []) or []

    # Gather data
    summary = _rpc_call(args, config, "summary") or {}
    parts = [f"# Analysis Report: {summary.get('binary', '?')}\n"]
    for key, label in [("jeb_version", "JEB Version"), ("class_count", "Classes"),
                       ("method_count", "Methods"), ("string_count", "Strings")]:
        parts.append(f"- {label}: {summary.get(key, '?')}")
    pkg, act = _extract_pkg_activity(summary)
    if pkg:
        parts.append(f"- Package: {pkg}")
    if act:
        parts.append(f"- Main Activity: {act}")
    parts.append("")

    # Decompile requested classes
    for sig in decompile_sigs:
        r = _rpc_call(args, config, "decompile", {"sig": sig})
        if r and r.get("code"):
            parts.append(f"## {sig}\n\n```java\n{r['code']}\n```\n")

    _save_local(out_path, "\n".join(parts))
    log.debug("cmd_report: saved to %s", out_path)
    _log_ok(f"Report saved to: {out_path}")
