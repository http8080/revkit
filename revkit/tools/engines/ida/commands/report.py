"""Report commands — bookmark, profile, report, annotations, snapshot, export-script."""

import json
import os
import sys
import time

from ..core import (
    post_rpc, _rpc_call, _resolve_ready,
    _opt, _save_local,
    _log_ok, _log_err, _log_info, _log_warn,
    _truncate, _md_table_header, _md_decompile, _md_summary,
    _format_arch_info, _print_truncated,
    load_registry,
    AUTO_GENERATED_PREFIXES, STRING_DISPLAY_LIMIT,
)
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Bookmark System
# ─────────────────────────────────────────────

_BOOKMARK_FILE = ".ida-bookmarks.json"


def _get_bookmark_path():
    return os.path.join(os.getcwd(), _BOOKMARK_FILE)


def _load_bookmarks():
    path = _get_bookmark_path()
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log.warning("_load_bookmarks: bookmark file not found or invalid JSON at %s", path)
        return {}


def _save_bookmarks(bookmarks):
    path = _get_bookmark_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bookmarks, f, ensure_ascii=False, indent=2)


def cmd_bookmark(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_bookmark: action=%s", action)
    bookmarks = _load_bookmarks()

    if action == "add":
        addr = args.addr
        tag = args.tag
        note = _opt(args, 'note') or ""
        binary_hint = _opt(args, 'binary_hint') or ""

        # Try to resolve binary name from active instance
        binary = binary_hint
        if binary_hint:
            registry = load_registry()
            for iid, info in registry.items():
                if binary_hint.lower() in info.get("binary", "").lower():
                    binary = info.get("binary", binary_hint)
                    break

        if binary not in bookmarks:
            bookmarks[binary] = []

        # Check for duplicate
        for bm in bookmarks[binary]:
            if bm["addr"] == addr and bm["tag"] == tag:
                _log_warn(f"Bookmark already exists: {addr} [{tag}]")
                return

        bookmarks[binary].append({
            "addr": addr,
            "tag": tag,
            "note": note,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        _save_bookmarks(bookmarks)
        _log_ok(f"Bookmark added: {addr} [{tag}] {note}")

    elif action == "remove":
        addr = args.addr
        binary_hint = _opt(args, 'binary_hint') or ""
        removed = False
        for binary in list(bookmarks.keys()):
            if binary_hint and binary_hint.lower() not in binary.lower():
                continue
            before = len(bookmarks[binary])
            bookmarks[binary] = [bm for bm in bookmarks[binary] if bm["addr"] != addr]
            if len(bookmarks[binary]) < before:
                removed = True
            if not bookmarks[binary]:
                del bookmarks[binary]
        if removed:
            _save_bookmarks(bookmarks)
            _log_ok(f"Bookmark removed: {addr}")
        else:
            _log_err(f"No bookmark found at {addr}")

    else:  # list
        tag_filter = _opt(args, 'tag')
        binary_filter = _opt(args, 'binary_hint')
        if not bookmarks:
            print("[*] No bookmarks. Use: ida-cli bookmark add <addr> <tag> [--note 'text']")
            return
        total = 0
        for binary, bms in sorted(bookmarks.items()):
            if binary_filter and binary_filter.lower() not in binary.lower():
                continue
            filtered = bms
            if tag_filter:
                filtered = [bm for bm in bms if tag_filter.lower() in bm["tag"].lower()]
            if not filtered:
                continue
            print(f"  {binary}:")
            for bm in filtered:
                note = f"  {bm['note']}" if bm.get('note') else ""
                print(f"    {bm['addr']}  [{bm['tag']}]{note}")
                total += 1
        print(f"\n  Total: {total} bookmarks")


# ─────────────────────────────────────────────
# Config Profiles
# ─────────────────────────────────────────────

_PROFILES = {
    "malware": {
        "description": "Malware analysis -focus on C2, crypto, anti-analysis",
        "analysis_steps": [
            "summary",
            "strings --filter http --count 30",
            "strings --filter socket --count 20",
            "strings --filter crypt --count 20",
            "imports --filter socket --count 30",
            "imports --filter crypt --count 30",
            "imports --filter process --count 30",
            "imports --filter registry --count 20",
            "find_func --regex 'crypt|encode|decode|xor|rc4|aes' --max 30",
            "find_func --regex 'connect|send|recv|http|url' --max 30",
            "find_func --regex 'inject|hook|patch|virtual' --max 20",
        ],
    },
    "firmware": {
        "description": "Firmware/IoT -focus on peripherals, protocols, boot",
        "analysis_steps": [
            "summary",
            "segments",
            "strings --filter uart --count 20",
            "strings --filter spi --count 20",
            "strings --filter gpio --count 20",
            "strings --filter error --count 30",
            "imports --count 50",
            "exports --count 50",
            "find_func --regex 'uart|spi|i2c|gpio|dma' --max 30",
            "find_func --regex 'init|setup|config|reset' --max 30",
            "find_func --regex 'read|write|send|recv' --max 30",
        ],
    },
    "vuln": {
        "description": "Vulnerability research -focus on dangerous functions, buffers",
        "analysis_steps": [
            "summary",
            "imports --filter memcpy --count 20",
            "imports --filter strcpy --count 20",
            "imports --filter sprintf --count 20",
            "imports --filter gets --count 10",
            "imports --filter system --count 10",
            "imports --filter exec --count 10",
            "imports --filter alloc --count 20",
            "find_func --regex 'parse|decode|deserialize|unpack' --max 30",
            "find_func --regex 'auth|login|verify|check_pass' --max 20",
            "find_func --regex 'handle|dispatch|process|callback' --max 30",
        ],
    },
}


_PROFILE_RPC_MAP = {
    "summary": "summary",
    "segments": "get_segments",
    "strings": "get_strings",
    "imports": "get_imports",
    "exports": "get_exports",
    "find_func": "find_func",
    "functions": "get_functions",
}


def _parse_profile_step(step, method):
    """Parse a profile step string into RPC params dict."""
    parts = step.split()
    params = {}
    i = 1
    while i < len(parts):
        if parts[i] == "--filter" and i + 1 < len(parts):
            params["filter"] = parts[i + 1]; i += 2
        elif parts[i] == "--count" and i + 1 < len(parts):
            params["count"] = int(parts[i + 1]); i += 2
        elif parts[i] == "--max" and i + 1 < len(parts):
            params["max_results"] = int(parts[i + 1]); i += 2
        elif parts[i] == "--regex":
            params["regex"] = True; i += 1
            if i < len(parts) and not parts[i].startswith("--"):
                params["name"] = parts[i].strip("'\""); i += 1
        else:
            if method == "find_func" and "name" not in params:
                params["name"] = parts[i].strip("'\"")
            i += 1
    return params


def _display_profile_result(method, r):
    """Display a profile step result."""
    if method == "summary":
        print(f"    Functions: {r.get('func_count')}  "
              f"Strings: {r.get('total_strings')}  "
              f"Imports: {r.get('total_imports')}  "
              f"Decompiler: {r.get('decompiler')}")
    elif method in ("strings", "imports", "exports", "functions"):
        data = r.get("data", [])
        total = r.get("total", 0)
        print(f"    Total: {total}, Showing: {len(data)}")
        for d in data[:10]:
            if "value" in d:
                print(f"      {d['addr']}  {_truncate(d['value'], 60)}")
            elif "module" in d:
                print(f"      {d['addr']}  {d.get('module', ''):<20}  {d['name']}")
            elif "name" in d:
                print(f"      {d['addr']}  {d['name']}")
        if len(data) > 10:
            print(f"      ... ({len(data) - 10} more)")
    elif method == "find_func":
        matches = r.get("matches", [])
        print(f"    Found: {r.get('total', 0)}")
        for m in matches[:10]:
            print(f"      {m['addr']}  {m['name']}")
        if len(matches) > 10:
            print(f"      ... ({len(matches) - 10} more)")
    elif method == "segments":
        for s in r.get("data", []):
            print(f"      {s['start_addr']}-{s['end_addr']}  "
                  f"{s.get('name') or '':<12}  {s.get('perm') or ''}")


def cmd_profile(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_profile: action=%s", action)

    if action == "list":
        print("  Available profiles:")
        for name, prof in _PROFILES.items():
            print(f"    {name:<12}  {prof['description']}")
        return

    if action == "run":
        profile_name = args.profile_name
        if profile_name not in _PROFILES:
            _log_err(f"Unknown profile: {profile_name}")
            print(f"    Available: {', '.join(_PROFILES.keys())}")
            return

        profile = _PROFILES[profile_name]
        log.debug("cmd_profile: running profile=%s steps=%d", profile_name, len(profile["analysis_steps"]))
        _log_info(f"Running profile: {profile_name} - {profile['description']}")
        print()

        iid, info, port = _resolve_ready(args, config)
        if not iid:
            return

        out_dir = _opt(args, 'out_dir')
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        for step in profile["analysis_steps"]:
            method = step.split()[0]
            print(f"  --- {step} ---")
            params = _parse_profile_step(step, method)
            if out_dir:
                params["output"] = os.path.join(out_dir, f"{method}_{params.get('filter', 'all')}.txt")
            rpc_method = _PROFILE_RPC_MAP.get(method, method)
            resp = post_rpc(config, port, rpc_method, iid, params=params)
            if "error" in resp:
                _log_err(f"  {resp['error'].get('message', '?')}")
                continue
            _display_profile_result(method, resp.get("result", {}))
            print()

        _log_ok(f"Profile '{profile_name}' complete")
        if out_dir:
            print(f"    Results saved to: {out_dir}")


# ─────────────────────────────────────────────
# Report Generation
# ─────────────────────────────────────────────

_REPORT_DATA_TABLES = [
    ("Imports", "get_imports", 100,
     ("Address", "Module", "Name"),
     lambda d: f"| `{d['addr']}` | {d.get('module', '')} | {d['name']} |"),
    ("Exports", "get_exports", 100,
     ("Address", "Name"),
     lambda d: f"| `{d['addr']}` | {d['name']} |"),
    ("Strings", "get_strings", 50,
     ("Address", "Value"),
     lambda d: f"| `{d['addr']}` | {d.get('value', '').replace('|', '\\|')} |"),
]


def _collect_report_data(config, port, iid, sections):
    """Collect imports/exports/strings into report sections."""
    for label, method, count, headers, fmt_row in _REPORT_DATA_TABLES:
        _log_info(f"Collecting {label.lower()}...")
        resp = post_rpc(config, port, method, iid, {"count": count})
        if "result" not in resp:
            continue
        data = resp["result"].get("data", [])
        total = resp["result"].get("total", 0)
        if not data:
            continue
        sections += [f"## {label} ({total} total, showing {len(data)})",
                     _md_table_header(*headers)]
        for d in data:
            sections.append(fmt_row(d))
        sections.append("")


def _collect_report_functions(config, port, iid, func_addrs, sections):
    """Decompile specific functions into report sections."""
    if not func_addrs:
        return
    sections += ["## Decompiled Functions", ""]
    for addr in func_addrs:
        _log_info(f"Decompiling {addr}...")
        resp = post_rpc(config, port, "decompile_with_xrefs", iid, {"addr": addr})
        if "result" in resp:
            sections.append(_md_decompile(resp["result"], with_xrefs=True))
        else:
            err = resp.get("error", {}).get("message", "unknown error")
            sections += [f"### `{addr}` - Error", f"> {err}"]
        sections.append("")


def _collect_report_bookmarks(binary_name, sections):
    """Add bookmarks to report sections."""
    bookmarks = _load_bookmarks()
    if not bookmarks:
        return
    bm_for_binary = {bn: bms for bn, bms in bookmarks.items()
                     if os.path.basename(binary_name).lower() in bn.lower()}
    if bm_for_binary:
        sections += ["## Bookmarks", _md_table_header("Address", "Tag", "Note")]
        for bms in bm_for_binary.values():
            for bm in bms:
                note = bm.get("note", "").replace("|", "\\|")
                sections.append(f"| `{bm['addr']}` | {bm['tag']} | {note} |")
        sections.append("")


def _collect_report_sections(config, port, iid, binary_name, func_addrs):
    """Collect all report sections from the running instance."""
    import datetime
    sections = []

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    sections.append(f"# Analysis Report: {os.path.basename(binary_name)}")
    sections.append(f"**Generated**: {ts}  ")
    sections.append(f"**Binary**: `{binary_name}`")
    sections.append("")

    _log_info("Collecting summary...")
    resp = post_rpc(config, port, "summary", iid)
    if "result" in resp:
        sections.append(_md_summary(resp["result"]))

    _collect_report_data(config, port, iid, sections)
    _collect_report_functions(config, port, iid, func_addrs, sections)
    _collect_report_bookmarks(binary_name, sections)

    sections += ["---", "*Generated by ida-cli report*"]
    return "\n".join(sections) + "\n"


_HTML_REPORT_STYLES = """\
body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
th { background: #f5f5f5; }
pre, code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
pre { padding: 12px; overflow-x: auto; }"""


def _render_html(content, binary_name):
    """Convert markdown content to HTML report."""
    try:
        import markdown
        html_body = markdown.markdown(content, extensions=["tables"])
    except ImportError:
        html_body = f"<pre>{content}</pre>"
    title = os.path.basename(binary_name)
    return (f'<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
            f'<title>Report: {title}</title>\n'
            f'<style>\n{_HTML_REPORT_STYLES}\n</style></head><body>\n'
            f'{html_body}\n</body></html>')


def cmd_report(ctx: CmdContext):
    """Generate markdown/HTML analysis report."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_report: output=%s", args.output)
    iid, info, port = _resolve_ready(args, config)
    if not iid:
        return
    out_path = args.output
    if not out_path:
        _log_err("Output file required: revkit ida report <output.md> or --report-out <path>")
        return
    binary_name = info.get("binary", "unknown")
    func_addrs = _opt(args, 'functions') or []

    content = _collect_report_sections(config, port, iid, binary_name, func_addrs)
    log.debug("cmd_report: generated %d chars of content", len(content))

    if out_path.lower().endswith('.html'):
        _save_local(out_path, _render_html(content, binary_name))
    else:
        _save_local(out_path, content)
    _log_ok(f"Report generated: {out_path}")


def cmd_annotations(ctx: CmdContext):
    """Export or import analysis annotations."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'export')
    log.debug("cmd_annotations: action=%s", action)

    if action == "export":
        out_path = _opt(args, 'out') or "annotations.json"
        p = {}
        r = _rpc_call(args, config, "export_annotations", p)
        if not r:
            return
        names_count = len(r.get("names", []))
        comments_count = len(r.get("comments", []))
        types_count = len(r.get("types", []))
        # Save locally
        log.debug("cmd_annotations: export names=%d comments=%d types=%d path=%s", names_count, comments_count, types_count, out_path)
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))
        print(f"  Names: {names_count}, Comments: {comments_count}, Types: {types_count}")

    elif action == "import":
        in_path = args.input_file
        log.debug("cmd_annotations: importing from %s", in_path)
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


def cmd_snapshot(ctx: CmdContext):
    """Manage IDB snapshots."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_snapshot: action=%s", action)

    if action == "save":
        desc = _opt(args, 'description', 'Snapshot') or 'Snapshot'
        r = _rpc_call(args, config, "snapshot_save", {"description": desc})
        if not r:
            return
        method = f" ({r.get('method', 'ida_api')})" if r.get("method") else ""
        print(f"  [+] Snapshot saved: {r.get('filename', '')}{method}")

    elif action == "list":
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
            desc = f"  \"{s['description']}\"" if s.get("description") else ""
            print(f"    {s['created']}  {size_mb:.1f}MB  {s['name']}{desc}")

    elif action == "restore":
        filename = args.filename
        r = _rpc_call(args, config, "snapshot_restore", {"filename": filename})
        if not r:
            return
        print(f"  [+] Restored from: {r.get('restored_from', '')}")
        print(f"      Current backed up to: {r.get('backup_of_current', '')}")
        if r.get("note"):
            print(f"      Note: {r['note']}")


def cmd_export_script(ctx: CmdContext):
    """Generate IDAPython script from analysis modifications."""
    args, config = ctx.args, ctx.config
    out_path = _opt(args, 'out', 'analysis.py') or 'analysis.py'
    log.debug("cmd_export_script: out=%s", out_path)
    p = {"output": out_path}
    r = _rpc_call(args, config, "export_script", p)
    if not r:
        log.debug("cmd_export_script: RPC returned None")
        return
    log.debug("cmd_export_script: renames=%d comments=%d types=%d", r.get("renames", 0), r.get("comments", 0), r.get("types", 0))
    print(f"  Renames:  {r.get('renames', 0)}")
    print(f"  Comments: {r.get('comments', 0)}")
    print(f"  Types:    {r.get('types', 0)}")
    saved = r.get("saved_to")
    if not saved and r.get("script"):
        _save_local(out_path, r["script"])
        saved = out_path
    if saved:
        print(f"  Saved to: {saved}")
