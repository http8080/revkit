"""Batch commands -- batch-analyze APK/DEX files."""

import logging
import os
import glob

from ..core import _log_ok, _log_err, _log_info, _opt
from .instance import cmd_start, cmd_wait, cmd_stop, _SimpleArgs
from ...base import CmdContext

log = logging.getLogger(__name__)


def cmd_batch(ctx: CmdContext):
    """Batch-analyze a directory of APK/DEX files."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    directory = args.directory
    log.debug("cmd_batch: directory=%s ext=%s", directory, _opt(args, 'ext', 'apk'))
    ext = _opt(args, 'ext', 'apk')
    keep = _opt(args, 'keep', False)
    timeout = _opt(args, 'timeout', 300)

    if not os.path.isdir(directory):
        _log_err(f"Directory not found: {directory}")
        return

    pattern = os.path.join(directory, f"*.{ext}")
    files = sorted(glob.glob(pattern))
    if not files:
        _log_info(f"No *.{ext} files found in {directory}")
        return

    log.debug("cmd_batch: found %d *.%s files", len(files), ext)
    _log_info(f"Found {len(files)} *.{ext} files")
    results = []

    for idx, filepath in enumerate(files, 1):
        basename = os.path.basename(filepath)
        _log_info(f"[{idx}/{len(files)}] {basename}")

        try:
            start_args = _SimpleArgs(
                binary=filepath, force=True, fresh=False,
                project_dir=None)
            start_ctx = CmdContext(args=start_args, config=config,
                                  config_path=config_path)
            iid = cmd_start(start_ctx)
            if not iid:
                results.append({"file": basename, "status": "error",
                                "error": "start failed"})
                _log_err(f"  Start failed for {basename}")
                continue

            # Wait for analysis to complete
            wait_args = _SimpleArgs(
                id=iid, timeout=timeout, instance=iid)
            wait_ctx = CmdContext(args=wait_args, config=config,
                                 config_path=config_path)
            cmd_wait(wait_ctx)

            results.append({"file": basename, "instance": iid, "status": "ok"})

            if not keep:
                stop_args = _SimpleArgs(id=iid, instance=iid)
                stop_ctx = CmdContext(args=stop_args, config=config,
                                     config_path=config_path)
                cmd_stop(stop_ctx)
        except Exception as e:
            log.warning("cmd_batch: exception for %s: %s", basename, e)
            results.append({"file": basename, "status": "error", "error": str(e)})
            _log_err(f"  Failed: {e}")

    log.debug("cmd_batch: completed %d files", len(results))
    print(f"\n  Batch complete: {len(results)} files")
    ok = sum(1 for r in results if r["status"] == "ok")
    print(f"  Success: {ok}, Failed: {len(results) - ok}")
    if keep:
        _log_info("Instances kept running (use 'stop' to terminate)")
