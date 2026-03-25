# -*- coding: utf-8 -*-
"""Snapshot handlers -- save/list/restore project snapshots.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

import json
import os
import time

from .helpers import _require_param, _to_str


def _get_snapshot_paths(self, require_file=True):
    """Return (prj_path, snap_dir) for snapshot operations.

    Raises RpcError if project path cannot be determined.
    """
    prj_path = getattr(self, "project_path", None)
    if not prj_path:
        try:
            prj_path = _to_str(self.prj.getPath())
        except Exception:
            pass
    if not prj_path or (require_file and not os.path.isfile(prj_path)):
        raise self.RpcError("SNAPSHOT_FAILED",
                            "Cannot determine project file path",
                            "Ensure the project was saved at least once with 'save'")
    snap_dir = os.path.join(os.path.dirname(prj_path), "snapshots")
    return prj_path, snap_dir


def _handle_snapshot_save(self, params):
    """Save a project snapshot (.jdb2 backup)."""
    description = params.get("description", "")

    try:
        self.ctx.saveProject(self.prj)
    except Exception:
        pass

    prj_path, snap_dir = _get_snapshot_paths(self)
    if not os.path.isdir(snap_dir):
        os.makedirs(snap_dir)

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(prj_path)
    snap_name = "%s_%s.bak" % (os.path.splitext(base)[0], ts)
    snap_path = os.path.join(snap_dir, snap_name)

    import shutil
    shutil.copy2(prj_path, snap_path)

    if description:
        meta_path = snap_path + ".meta"
        content = json.dumps({"description": description,
                       "created": ts,
                       "source": prj_path}, ensure_ascii=True)
        with open(meta_path, "w") as f:
            f.write(content)

    return {"ok": True, "filename": snap_name, "description": description}


def _handle_snapshot_list(self, params):
    """List available snapshots."""
    try:
        _prj_path, snap_dir = _get_snapshot_paths(self, require_file=False)
    except Exception:
        return {"total": 0, "snapshots": []}

    if not os.path.isdir(snap_dir):
        return {"total": 0, "snapshots": []}

    snapshots = []
    for fname in sorted(os.listdir(snap_dir)):
        if not fname.endswith(".bak"):
            continue
        fpath = os.path.join(snap_dir, fname)
        stat = os.stat(fpath)

        desc = ""
        meta_path = fpath + ".meta"
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                desc = meta.get("description", "")
            except Exception:
                pass

        snapshots.append({
            "filename": fname,
            "created": time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(stat.st_mtime)),
            "size": stat.st_size,
            "description": desc,
        })

    return {"total": len(snapshots), "snapshots": snapshots}


def _handle_snapshot_restore(self, params):
    """Restore a project from a snapshot."""
    import shutil

    filename = _require_param(self, params, "filename")

    prj_path, snap_dir = _get_snapshot_paths(self)
    snap_path = os.path.join(snap_dir, filename)

    if not os.path.isfile(snap_path):
        raise self.RpcError("SNAPSHOT_NOT_FOUND",
                            "Snapshot not found: %s" % filename,
                            "Use 'snapshot list' to see available snapshots")

    # Auto-backup before restoring
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(prj_path)
    auto_backup = os.path.join(snap_dir,
                               "%s_pre_restore_%s.bak" % (
                                   os.path.splitext(base)[0], ts))
    try:
        shutil.copy2(prj_path, auto_backup)
    except Exception:
        pass

    shutil.copy2(snap_path, prj_path)
    return {"ok": True, "filename": filename}
