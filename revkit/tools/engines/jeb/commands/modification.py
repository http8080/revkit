"""Modification commands -- rename, comment, undo, bookmark."""

import json
import logging
import os
import time

from ..core import (
    _rpc_call, _opt, _log_ok, _log_err, _log_info,
    _truncate, _build_params,
)
from ...base import CmdContext

log = logging.getLogger(__name__)


# =============================================================
# Undo history
# =============================================================

_UNDO_FILE = os.path.join(os.path.expanduser("~"), ".jeb-cli", "undo_history.json")


def _save_undo(action_type, data):
    """Save undo entry to local history file."""
    os.makedirs(os.path.dirname(_UNDO_FILE), exist_ok=True)
    try:
        with open(_UNDO_FILE, encoding="utf-8") as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log.warning("_save_undo: undo history file missing or corrupt, starting fresh")
        history = []
    history.append({"type": action_type, "data": data,
                    "timestamp": time.time()})
    # Keep last 50 entries
    history = history[-50:]
    with open(_UNDO_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


def _pop_undo():
    """Pop the last undo entry."""
    try:
        with open(_UNDO_FILE, encoding="utf-8") as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if not history:
        return None
    entry = history.pop()
    with open(_UNDO_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)
    return entry


# =============================================================
# Bookmark
# =============================================================

_BOOKMARK_FILE = os.path.join(os.path.expanduser("~"), ".jeb-cli", "bookmarks.json")


def _load_bookmarks():
    try:
        with open(_BOOKMARK_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_bookmarks(bookmarks):
    os.makedirs(os.path.dirname(_BOOKMARK_FILE), exist_ok=True)
    with open(_BOOKMARK_FILE, "w", encoding="utf-8") as f:
        json.dump(bookmarks, f, ensure_ascii=False, indent=2)


# =============================================================
# Rename helpers
# =============================================================

def _cmd_rename_typed(args, config, rpc_method, sig_attr, label):
    """Shared rename handler for class/method/field."""
    r = _rpc_call(args, config, rpc_method,
                  {"sig": getattr(args, sig_attr), "new_name": args.new_name})
    if r:
        _log_ok(f"Renamed {label} {r.get('old_name', '')} -> {r.get('new_name', '')}")


# =============================================================
# Rename commands
# =============================================================

def cmd_rename(ctx: CmdContext):
    """Rename a class, method, or field (auto-detect by signature)."""
    args, config = ctx.args, ctx.config
    sig = args.sig
    log.debug("cmd_rename: sig=%s new_name=%s", sig, args.new_name)
    # Determine type from signature format
    if "(" in sig:
        rpc = "rename_method"
    elif "->" in sig:
        rpc = "rename_field"
    else:
        rpc = "rename_class"
    # #38: --preview mode
    if _opt(args, 'preview', False):
        cmd_rename_preview(ctx)
        return
    r = _rpc_call(args, config, rpc, {"sig": sig, "new_name": args.new_name})
    if r:
        # #36: save undo entry
        _save_undo("rename", {"sig": sig, "old_name": r.get('old_name', ''),
                               "new_name": args.new_name, "rpc": rpc})
        _log_ok(f"Renamed {r.get('old_name', '')} -> {r.get('new_name', '')}")


def cmd_rename_class(ctx: CmdContext):
    """Rename a class."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_rename_class: class_sig=%s new_name=%s", args.class_sig, args.new_name)
    _cmd_rename_typed(args, config, "rename_class", "class_sig", "class")


def cmd_rename_method(ctx: CmdContext):
    """Rename a method."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_rename_method: method_sig=%s new_name=%s", args.method_sig, args.new_name)
    _cmd_rename_typed(args, config, "rename_method", "method_sig", "method")


def cmd_rename_field(ctx: CmdContext):
    """Rename a field."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_rename_field: field_sig=%s new_name=%s", args.field_sig, args.new_name)
    _cmd_rename_typed(args, config, "rename_field", "field_sig", "field")


def cmd_rename_batch(ctx: CmdContext):
    """Batch rename from a JSON file [{sig, new_name}, ...]."""
    args, config = ctx.args, ctx.config
    input_file = args.json_file
    log.debug("cmd_rename_batch: file=%s", input_file)
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
                entries = [{"sig": k, "new_name": v} for k, v in data.items()]
    else:
        # CSV format: sig,new_name (one per line)
        with open(input_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                if len(parts) == 2:
                    entries.append({"sig": parts[0].strip(), "new_name": parts[1].strip()})

    if not entries:
        _log_err("No rename entries found in file")
        return

    _log_info(f"Renaming {len(entries)} items...")
    r = _rpc_call(args, config, "rename_batch", {"entries": entries})
    if not r:
        log.warning("cmd_rename_batch: RPC returned None")
        return
    log.debug("cmd_rename_batch: %d/%d succeeded", r.get('success', 0), r.get('total', 0))
    print(f"  Total: {r.get('total', 0)}, Success: {r.get('success', 0)}, Failed: {r.get('failed', 0)}")
    for entry in r.get("results", r.get("renames", []))[:30]:
        status = "OK" if entry.get("ok") else "FAIL"
        print(f"    [{status}] {entry.get('sig', '')}  -> {entry.get('new_name', '')}")


def cmd_rename_preview(ctx: CmdContext):
    """#38: Show impact of a rename without applying it."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_rename_preview: sig=%s new_name=%s", args.sig, args.new_name)
    sig = args.sig
    new_name = args.new_name
    # Get xrefs to see what would be affected
    r = _rpc_call(args, config, "get_xrefs_to", {"sig": sig})
    if not r:
        _log_info("No cross-references found (rename would have no side effects)")
        return
    refs = r.get("refs", [])
    print(f"Rename preview: {sig} -> {new_name}")
    print(f"  Affected references: {len(refs)}")
    for ref in refs[:30]:
        method_sig = ref.get('method_sig', ref.get('address', ''))
        ref_type = ref.get('type', '')
        print(f"    {method_sig}  [{ref_type}]")
    if len(refs) > 30:
        print(f"    ... and {len(refs) - 30} more")
    _log_info("Use 'rename' without --preview to apply")


def cmd_auto_rename(ctx: CmdContext):
    """Heuristic auto-rename of obfuscated classes/methods."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_auto_rename: apply=%s max_classes=%s", _opt(args, 'apply', False), _opt(args, 'max_classes', 100))
    apply = _opt(args, 'apply', False)
    p = {"max_classes": _opt(args, 'max_classes', 100), "apply": apply}
    r = _rpc_call(args, config, "auto_rename", p)
    if not r:
        log.warning("cmd_auto_rename: RPC returned None")
        return
    suggestions = r.get("suggestions", [])
    log.debug("cmd_auto_rename: %d suggestions, %d applied", len(suggestions), r.get('applied', 0))
    applied = r.get("applied", 0)
    print(f"  Suggestions: {len(suggestions)}, Applied: {applied}")
    for s in suggestions[:50]:
        status = "APPLIED" if s.get("applied") else "SUGGEST"
        reason = s.get("reason", "")
        reason_str = f'  ("{_truncate(reason, 30)}")' if reason else ""
        print(f"    [{status}] {s.get('old_name', ''):<40} -> {s.get('new_name', '')}{reason_str}")
    if not apply and suggestions:
        _log_info("Use --apply to apply renames")


# =============================================================
# Comment commands
# =============================================================

def cmd_set_comment(ctx: CmdContext):
    """Set a comment at a given address or signature."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_set_comment: addr=%s", args.addr)
    # #36: get old comment for undo before setting new one
    old_r = _rpc_call(args, config, "get_comments", {"addr": args.addr})
    old_comment = ""
    if old_r:
        old_comment = old_r.get("comment", "")
    p = {"address": args.addr, "comment": args.text}
    if _opt(args, 'type'):
        p["type"] = args.type
    r = _rpc_call(args, config, "set_comment", p)
    if r:
        _save_undo("comment", {"addr": args.addr, "old_comment": old_comment,
                                "new_comment": args.text})
        _log_ok(f"Comment set at {r.get('address', args.addr)}")


def cmd_get_comments(ctx: CmdContext):
    """Get comments (all or at a specific address)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_get_comments: addr=%s", _opt(args, 'addr'))
    p = {}
    addr = _opt(args, 'addr')
    if addr:
        p["address"] = addr
    r = _rpc_call(args, config, "get_comments", p)
    if not r:
        return
    comments = r.get("comments", [])
    if not comments:
        _log_info("No comments found")
        return
    # Server may return dict {addr: text} or list [{address, type, text}]
    if isinstance(comments, dict):
        print(f"  Comments ({len(comments)}):")
        for addr, text in comments.items():
            print(f"    {addr:<40}  {_truncate(str(text), 60)}")
    else:
        print(f"  Comments ({len(comments)}):")
        for c in comments:
            if isinstance(c, dict):
                print(f"    {c.get('address', ''):<40}  {c.get('type', ''):<8}  {_truncate(c.get('text', ''), 60)}")
            else:
                print(f"    {c}")


# =============================================================
# Undo / Bookmark commands
# =============================================================

def cmd_undo(ctx: CmdContext):
    """#36: Undo the last rename or comment operation."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_undo: trying server-side undo first")
    # Try server-side undo first (has history from rename_class, set_comment, etc.)
    r = _rpc_call(args, config, "undo")
    if r and r.get("ok"):
        action = r.get("action", "")
        reverted = r.get("reverted", "")
        addr = r.get("addr", "")
        if "rename" in action:
            _log_ok(f"Undone rename: {reverted}")
        elif "comment" in action:
            _log_ok(f"Undone comment at {addr}")
        else:
            _log_ok(f"Undone: {action}")
        return
    # Fallback to client-side undo history
    log.debug("cmd_undo: server undo failed, trying client-side")
    entry = _pop_undo()
    if not entry:
        _log_info("No undo history available")
        return
    action = entry["type"]
    data = entry["data"]
    if action == "rename":
        sig = data.get("sig")
        old_name = data.get("old_name")
        rpc = data.get("rpc", "rename_class")
        r2 = _rpc_call(args, config, rpc, {"sig": sig, "new_name": old_name})
        if r2:
            _log_ok(f"Undone rename: {data.get('new_name', '')} -> {old_name}")
    elif action == "comment":
        addr = data.get("addr")
        old_comment = data.get("old_comment", "")
        r2 = _rpc_call(args, config, "set_comment",
                       {"address": addr, "comment": old_comment})
        if r2:
            _log_ok(f"Undone comment at {addr}")
    else:
        _log_err(f"Unknown undo action: {action}")


def cmd_bookmark(ctx: CmdContext):
    """#37: Add, list, or remove bookmarks."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_bookmark: action=%s", action)
    bookmarks = _load_bookmarks()

    if action == "add":
        sig = args.sig
        note = _opt(args, 'note', '')
        # Check for duplicate
        for bm in bookmarks:
            if bm.get("sig") == sig:
                bm["note"] = note
                bm["updated"] = time.time()
                _save_bookmarks(bookmarks)
                _log_ok(f"Updated bookmark: {sig}")
                return
        bookmarks.append({"sig": sig, "note": note, "created": time.time()})
        _save_bookmarks(bookmarks)
        _log_ok(f"Bookmarked: {sig}")

    elif action == "remove":
        sig = args.sig
        before = len(bookmarks)
        bookmarks = [b for b in bookmarks if b.get("sig") != sig]
        if len(bookmarks) < before:
            _save_bookmarks(bookmarks)
            _log_ok(f"Removed bookmark: {sig}")
        else:
            _log_err(f"Bookmark not found: {sig}")

    else:  # list
        if not bookmarks:
            _log_info("No bookmarks")
            return
        if _opt(args, 'json', False):
            print(json.dumps({"bookmarks": bookmarks, "count": len(bookmarks)},
                              ensure_ascii=False, indent=2))
            return
        print(f"Bookmarks ({len(bookmarks)}):")
        for bm in bookmarks:
            note = bm.get("note", "")
            note_str = f'  "{note}"' if note else ""
            print(f"  {bm.get('sig', '')}{note_str}")
