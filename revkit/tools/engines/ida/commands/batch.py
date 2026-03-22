"""Batch analysis command — analyze all binaries in a directory."""

import os
import time

from ..core import (
    post_rpc, _log_ok, _log_err, _log_info, _opt,
    _format_arch_info,
    _register_instance, _spawn_server, _wait_for_start,
    make_instance_id, get_idb_path,
    load_registry,
    SUPPORTED_BINARY_EXTENSIONS,
)
from ..core import arch_detect
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


def _find_binaries(target_dir):
    """Find binary files in a directory by extension or magic bytes."""
    binaries = []
    for f in sorted(os.listdir(target_dir)):
        fpath = os.path.join(target_dir, f)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext in SUPPORTED_BINARY_EXTENSIONS:
            binaries.append(fpath)
            continue
        if not ext:
            try:
                with open(fpath, "rb") as fp:
                    magic = fp.read(4)
                if magic[:4] == b"\x7fELF" or magic[:2] == b"MZ":
                    binaries.append(fpath)
            except Exception:
                log.warning("_find_binaries: failed to read magic bytes from %s", fpath)
    return binaries


def _start_batch_instances(batch, config, config_path, idb_dir, fresh):
    """Start analysis instances for a batch of binaries. Returns [(iid, bname)]."""
    started = []
    for bpath in batch:
        bname = os.path.basename(bpath)
        norm_path = os.path.normcase(os.path.abspath(bpath))
        arch_info = arch_detect(bpath)
        instance_id = make_instance_id(bpath)
        idb_path = get_idb_path(config, norm_path, instance_id, False, idb_dir=idb_dir)
        log_path = os.path.join(config.get("paths", {}).get("log_dir", ""), f"{instance_id}.log")

        if not _register_instance(config, instance_id, norm_path,
                                   arch_info, idb_path, log_path, False):
            _log_err(f"{bname}: failed to register")
            continue
        try:
            _spawn_server(config, config_path, norm_path, instance_id, idb_path, log_path, fresh)
            _log_ok(f"{bname} ({_format_arch_info(arch_info)}) -> {instance_id}")
            started.append((instance_id, bname))
        except Exception as e:
            _log_err(f"{bname}: {e}")
    return started


def _wait_batch_instances(started, config, timeout):
    """Wait for batch instances to reach ready/error state."""
    deadline = time.time() + timeout
    poll = config.get("analysis", {}).get("wait_poll_interval", 1.0)
    pending = set(iid for iid, _ in started)
    while pending and time.time() < deadline:
        time.sleep(poll)
        registry = load_registry()
        for iid in list(pending):
            state = registry.get(iid, {}).get("state", "unknown")
            if state in ("ready", "error"):
                pending.discard(iid)


def _collect_batch_results(started, config):
    """Collect summary results from batch instances."""
    results = []
    registry = load_registry()
    for iid, bname in started:
        info = registry.get(iid, {})
        state = info.get("state", "unknown")
        port = info.get("port")
        if state == "ready" and port:
            resp = post_rpc(config, port, "summary", iid)
            if "result" in resp:
                r = resp["result"]
                results.append((bname, iid, r))
                print(f"  {bname:<30}  funcs={r['func_count']:<6}  "
                      f"strings={r['total_strings']:<6}  "
                      f"imports={r['total_imports']:<6}  "
                      f"decompiler={'Y' if r['decompiler'] else 'N'}")
            else:
                print(f"  {bname:<30}  [ready but summary failed]")
        else:
            print(f"  {bname:<30}  [{state}]")
    return results


def cmd_batch(ctx: CmdContext):
    """Analyze all binaries in a directory."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    target_dir = os.path.abspath(args.directory)
    log.debug("cmd_batch: directory=%s", target_dir)
    if not os.path.isdir(target_dir):
        _log_err(f"Not a directory: {target_dir}")
        return

    binaries = _find_binaries(target_dir)
    log.debug("cmd_batch: found %d binaries", len(binaries))
    if not binaries:
        _log_err(f"No binaries found in: {target_dir}")
        return

    idb_dir = _opt(args, 'idb_dir') or os.environ.get('IDA_IDB_DIR')
    fresh = _opt(args, 'fresh', False)
    timeout = _opt(args, 'timeout', 300)
    max_concurrent = config.get("analysis", {}).get("max_instances", 3)

    _log_info(f"Found {len(binaries)} binaries in {target_dir}")
    _log_info(f"Max concurrent: {max_concurrent}, Timeout: {timeout}s")
    if idb_dir:
        _log_info(f"IDB dir: {idb_dir}")
    print()

    results = []
    for batch_start in range(0, len(binaries), max_concurrent):
        batch = binaries[batch_start:batch_start + max_concurrent]
        started = _start_batch_instances(batch, config, config_path, idb_dir, fresh)
        if not started:
            continue
        _log_info(f"Waiting for {len(started)} instances...")
        _wait_batch_instances(started, config, timeout)
        results.extend(_collect_batch_results(started, config))

    log.debug("cmd_batch: completed %d/%d", len(results), len(binaries))
    _log_ok(f"Batch complete: {len(results)}/{len(binaries)} analyzed")
    if results:
        print(f"\n  Active instances:")
        for bname, iid, _ in results:
            print(f"    {iid}  {bname}")
        print(f"\n  Use 'ida-cli -b <hint> decompile <addr>' to analyze further")
        if not _opt(args, 'keep', False):
            print(f"  Use 'ida-cli stop <id>' to stop, or 'ida-cli cleanup' to clean all")
