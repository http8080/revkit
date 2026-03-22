"""Snapshot API — save, list, restore IDB snapshots."""

import os

from ..framework import RpcError, _require_param


def _handle_snapshot_save(params):
    """Save IDB snapshot."""
    import ida_loader, ida_kernwin
    desc = params.get("description", "Snapshot")
    ok = ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)
    try:
        ss = ida_kernwin.snapshot_t()
        ss.desc = desc
        ok = ida_kernwin.take_database_snapshot(ss)
        return {"ok": bool(ok), "description": desc, "filename": ss.filename if ok else ""}
    except Exception as e:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        import shutil, datetime, json as _json
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = f"{idb_path}.snapshot_{ts}"
        shutil.copy2(idb_path, backup)
        meta = {"description": desc, "created": datetime.datetime.now().isoformat()}
        with open(backup + ".meta.json", "w", encoding="utf-8") as mf:
            _json.dump(meta, mf, ensure_ascii=False)
        return {"ok": True, "description": desc, "filename": backup, "method": "file_copy"}


def _handle_snapshot_list(params):
    """List available snapshots."""
    import ida_loader, glob as glob_mod, datetime, json as _json
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    pattern = f"{idb_path}.snapshot_*"
    snapshots = []
    for f in sorted(glob_mod.glob(pattern)):
        if f.endswith(".meta.json"):
            continue
        name = os.path.basename(f)
        mtime = os.path.getmtime(f)
        entry = {
            "filename": f,
            "name": name,
            "size": os.path.getsize(f),
            "created": datetime.datetime.fromtimestamp(mtime).isoformat(),
        }
        meta_path = f + ".meta.json"
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as mf:
                    meta = _json.load(mf)
                entry["description"] = meta.get("description", "")
            except Exception:
                pass
        snapshots.append(entry)
    return {"total": len(snapshots), "snapshots": snapshots}


def _handle_snapshot_restore(params):
    """Restore IDB from a snapshot file."""
    import ida_loader, shutil
    filename = _require_param(params, "filename")
    if not os.path.isfile(filename):
        idb_dir = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        candidate = os.path.join(idb_dir, filename)
        if os.path.isfile(candidate):
            filename = candidate
        else:
            raise RpcError("FILE_NOT_FOUND", f"Snapshot file not found: {filename}")
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = f"{idb_path}.before_restore_{ts}"
    shutil.copy2(idb_path, backup)
    shutil.copy2(filename, idb_path)
    return {
        "ok": True,
        "restored_from": filename,
        "backup_of_current": backup,
        "note": "Restart instance to load restored snapshot",
    }
