"""Type management commands — structs, enums, type_info, vtables, sigs."""

from ..core import (
    _rpc_call, _opt, _build_params, _truncate, _log_ok,
)
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


def cmd_structs(ctx: CmdContext):
    """Manage structs and unions."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_structs: action=%s", action)

    if action == "list":
        p = _build_params(args, {"filter": "filter"})
        r = _rpc_call(args, config, "list_structs", p)
        if not r:
            return
        items = r.get("structs", [])
        total = len(items)
        offset = _opt(args, 'offset', 0) or 0
        count = _opt(args, 'count') or len(items)
        items = items[offset:offset + count]
        print(f"  Total: {total}" + (f" (showing {len(items)} from offset {offset})" if offset or count < total else ""))
        for s in items:
            kind = "union" if s.get("is_union") else "struct"
            print(f"    {s['name']:<30}  {kind:<6}  size={s['size']:<6}  members={s['member_count']}")

    elif action == "show":
        r = _rpc_call(args, config, "get_struct", {"name": args.name})
        if not r:
            return
        kind = "union" if r.get("is_union") else "struct"
        print(f"  {kind} {r['name']} (size={r['size']})")
        print(f"  {'Offset':<8}  {'Name':<24}  {'Size':<6}  Type")
        print(f"  {'-'*8}  {'-'*24}  {'-'*6}  {'-'*20}")
        for m in r.get("members", []):
            print(f"  {m['offset']:<8}  {m['name']:<24}  {m['size']:<6}  {m.get('type', '')}")

    elif action == "create":
        p = {"name": args.name}
        if _opt(args, 'union', False):
            p["is_union"] = True
        members = []
        for mdef in (_opt(args, 'members') or []):
            parts = mdef.split(":")
            mname = parts[0]
            if len(parts) > 1:
                try:
                    msize = int(parts[1])
                    members.append({"name": mname, "size": msize})
                except ValueError:
                    # treat as type name (e.g. "f1:int" → type="int")
                    members.append({"name": mname, "type": parts[1]})
            else:
                members.append({"name": mname, "size": 1})
        if members:
            p["members"] = members
        r = _rpc_call(args, config, "create_struct", p)
        if not r:
            return
        print(f"  [+] Struct created: {args.name} (members: {r.get('members_added', 0)})")


def cmd_enums(ctx: CmdContext):
    """Manage enums."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_enums: action=%s", action)

    if action == "list":
        p = {}
        if _opt(args, 'filter'):
            p["filter"] = args.filter
        r = _rpc_call(args, config, "list_enums", p)
        if not r:
            return
        items = r.get("enums", [])
        total = len(items)
        offset = _opt(args, 'offset', 0) or 0
        count = _opt(args, 'count') or len(items)
        items = items[offset:offset + count]
        print(f"  Total: {total}" + (f" (showing {len(items)} from offset {offset})" if offset or count < total else ""))
        for e in items:
            print(f"    {e['name']:<30}  members={e['member_count']}")

    elif action == "show":
        r = _rpc_call(args, config, "get_enum", {"name": args.name})
        if not r:
            return
        print(f"  enum {r['name']} ({r['total']} members)")
        for m in r.get("members", []):
            print(f"    {m['name']:<30} = {m['value']}")

    elif action == "create":
        p = {"name": args.name}
        members = []
        for mdef in (_opt(args, 'members') or []):
            parts = mdef.split("=")
            mname = parts[0].strip()
            mval = parts[1].strip() if len(parts) > 1 else ""
            members.append({"name": mname, "value": mval})
        if members:
            p["members"] = members
        r = _rpc_call(args, config, "create_enum", p)
        if not r:
            return
        print(f"  [+] Enum created: {args.name} (members: {r.get('members_added', 0)})")


def cmd_type_info(ctx: CmdContext):
    """Query IDA local types."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_type_info: action=%s", action)

    if action == "list":
        p = {}
        if _opt(args, 'filter'):
            p["filter"] = args.filter
        if _opt(args, 'kind'):
            p["kind"] = args.kind
        if _opt(args, 'offset') is not None:
            p["offset"] = args.offset
        if _opt(args, 'count') is not None:
            p["count"] = args.count
        r = _rpc_call(args, config, "list_types", p)
        if not r:
            return
        print(f"  Total: {r.get('total', 0)} (showing {r.get('count', 0)} from offset {r.get('offset', 0)})")
        for t in r.get("data", []):
            print(f"    {t['name']:<40}  {t.get('kind', ''):<8}  size={t.get('size', '?')}")

    elif action == "show":
        r = _rpc_call(args, config, "get_type", {"name": args.name})
        if not r:
            return
        print(f"  Name:        {r['name']}")
        print(f"  Size:        {r.get('size', '?')}")
        print(f"  Declaration: {r.get('declaration', '')}")
        flags = []
        for f in ("is_struct", "is_union", "is_enum", "is_typedef", "is_funcptr"):
            if r.get(f):
                flags.append(f.replace("is_", ""))
        if flags:
            print(f"  Type:        {', '.join(flags)}")
        if r.get("return_type"):
            print(f"  Return:      {r['return_type']}")
        if r.get("args"):
            print(f"  Args:")
            for a in r["args"]:
                print(f"    {a['type']:<30}  {a['name']}")


def cmd_vtables(ctx: CmdContext):
    """Detect virtual function tables."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_vtables: detecting vtables")
    p = {}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    if _opt(args, 'min_entries'):
        p["min_entries"] = args.min_entries
    r = _rpc_call(args, config, "detect_vtables", p)
    if not r:
        log.debug("cmd_vtables: RPC returned None")
        return
    log.debug("cmd_vtables: detected %d vtables", r.get("total", 0))
    print(f"  Detected: {r.get('total', 0)} vtables (ptr_size={r.get('ptr_size', 8)})")
    for vt in r.get("vtables", []):
        print(f"\n    {vt['addr']}  ({vt['entries']} entries)")
        for fn in vt.get("functions", [])[:10]:
            print(f"      +{fn['offset']:<4}  {fn['addr']}  {fn['name']}")
        if vt["entries"] > 10:
            print(f"      ... ({vt['entries'] - 10} more)")


def cmd_sigs(ctx: CmdContext):
    """Manage FLIRT signatures."""
    args, config = ctx.args, ctx.config
    action = _opt(args, 'action', 'list')
    log.debug("cmd_sigs: action=%s", action)

    if action == "list":
        r = _rpc_call(args, config, "list_sigs")
        if not r:
            return
        print(f"  Sig dir: {r.get('sig_dir', '')}")
        print(f"  Total: {r.get('total', 0)}")
        for s in r.get("signatures", []):
            size_kb = s.get("size", 0) / 1024
            print(f"    {s['name']:<40}  {size_kb:.1f}KB")

    elif action == "apply":
        sig_name = args.sig_name
        r = _rpc_call(args, config, "apply_sig", {"name": sig_name})
        if not r:
            return
        print(f"  [+] Applied signature: {sig_name}")
