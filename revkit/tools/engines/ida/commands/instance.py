"""Instance management commands — start, stop, restart, wait, list, status, logs, cleanup."""

import json
import os
import sys
import time
import glob

from ..core import (
    _log_ok, _log_err, _log_info, _log_warn,
    _opt, _format_arch_info,
    _registry_locked, _make_args,
    _is_process_alive, cleanup_stale, _force_kill,
    _register_instance, _spawn_server, _wait_for_start,
    load_config, _load_idb_metadata,
    load_registry, save_registry, remove_auth_token,
    make_instance_id, get_idb_path,
    resolve_instance,
    post_rpc, psutil,
    SUPPORTED_BINARY_EXTENSIONS,
    STOP_WAIT_ITERATIONS, STOP_POLL_INTERVAL, STOP_RPC_TIMEOUT,
    CLEANUP_AGE_SECONDS, PID_CREATE_TIME_TOLERANCE,
)
from ..core import arch_detect
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


def cmd_init(ctx: CmdContext):
    log.debug("cmd_init: creating directories")
    config = ctx.config
    ida_reg = config.get("ida", {}).get("registry", "~/.revkit/ida/registry.json")
    ida_reg = os.path.expanduser(ida_reg)
    _paths = config.get("paths", {})
    dirs = [_paths.get("idb_dir", ""), _paths.get("log_dir", ""),
            os.path.dirname(ida_reg)]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        _log_ok(d)
    _log_ok("Init complete")


def cmd_check(ctx: CmdContext):
    log.debug("cmd_check: running environment checks")
    config = ctx.config
    issues = []
    print(f"  Python: {sys.version.split()[0]}")
    if sys.version_info < (3, 10):
        issues.append("Python 3.10+ required")
    try:
        import importlib.util
        spec = importlib.util.find_spec("idapro")
        print(f"  idapro: {'found' if spec else 'NOT FOUND'}")
        if not spec:
            issues.append("idapro not found")
    except Exception:
        log.warning("cmd_check: idapro check raised exception")
        issues.append("idapro check failed")
    ida_dir = config.get("ida", {}).get("install_dir", "")
    ok = os.path.isdir(ida_dir)
    print(f"  IDA dir: {ida_dir} ({'OK' if ok else 'NOT FOUND'})")
    if not ok:
        issues.append(f"IDA dir not found: {ida_dir}")
    from ..core import req_lib
    for pkg_name, mod in [("requests", req_lib), ("psutil", psutil)]:
        if mod:
            print(f"  {pkg_name}: {getattr(mod, '__version__', 'found')}")
        else:
            issues.append(f"{pkg_name} not installed")
            print(f"  {pkg_name}: NOT FOUND")
    if issues:
        print(f"\n[-] {len(issues)} issue(s):")
        for i in issues:
            print(f"  - {i}")
    else:
        print("\n[+] All checks passed")


def cmd_start(ctx: CmdContext):
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    log.debug("cmd_start: binary=%s", args.binary)
    binary_path = os.path.normcase(os.path.abspath(args.binary))
    if not os.path.isfile(binary_path):
        _log_err(f"Binary not found: {binary_path}")
        return

    arch_info = arch_detect(binary_path, _opt(args, 'arch'))
    instance_id = make_instance_id(binary_path)
    force = _opt(args, 'force', False)
    fresh = _opt(args, 'fresh', False)
    idb_dir_override = _opt(args, 'idb_dir') or os.environ.get('IDA_IDB_DIR')
    idb_path = get_idb_path(config, binary_path, instance_id, force, idb_dir=idb_dir_override)

    if os.path.exists(idb_path) and not fresh:
        meta = _load_idb_metadata(idb_path)
        stored_md5 = meta.get("binary_md5")
        if stored_md5:
            from ..core import file_md5
            current_md5 = file_md5(binary_path)
            if stored_md5 != current_md5:
                _log_warn("Binary changed since .i64 was created.")
                if not force:
                    print("  Use --fresh to rebuild, or --force to proceed.")
                    return

    log_path = os.path.join(config.get("paths", {}).get("log_dir", ""), f"{instance_id}.log")
    if not _register_instance(config, instance_id, binary_path, arch_info,
                               idb_path, log_path, force):
        return

    proc = _spawn_server(config, config_path, binary_path, instance_id, idb_path, log_path, fresh)
    state = _wait_for_start(instance_id)

    log.debug("cmd_start: instance=%s state=%s pid=%d", instance_id, state, proc.pid)
    _log_ok(f"Instance started: {instance_id}")
    print(f"    Binary:  {os.path.basename(binary_path)} ({_format_arch_info(arch_info)})")
    print(f"    IDB:     {idb_path}")
    print(f"    Log:     {log_path}")
    print(f"    State:   {state}")
    print(f"    PID:     {proc.pid}")
    if state == "error":
        _log_err(f"Analysis failed. Check: ida_cli.py logs {instance_id}")
    elif state in ("initializing", "analyzing"):
        _log_info(f"Still {state}. Use: ida_cli.py wait {instance_id}")


def cmd_stop(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    iid = args.id
    log.debug("cmd_stop: id=%s", iid)
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
        return
    port = info.get("port")
    pid = info.get("pid")

    if port:
        try:
            post_rpc(config, port, "stop", iid, timeout=STOP_RPC_TIMEOUT)
            for _ in range(STOP_WAIT_ITERATIONS):
                time.sleep(STOP_POLL_INTERVAL)
                if iid not in load_registry():
                    _log_ok(f"Instance {iid} stopped normally")
                    return
        except Exception:
            log.warning("cmd_stop: RPC stop failed for %s, falling back to force kill", iid)

    if pid:
        _force_kill(iid, pid, info.get("pid_create_time"))

    try:
        with _registry_locked():
            r = load_registry()
            r.pop(iid, None)
            save_registry(r)
    except RuntimeError:
        log.warning("cmd_stop: could not acquire registry lock for %s", iid)
    remove_auth_token(config.get("security", {}).get("auth_token_file", ""), iid)


def cmd_restart(ctx: CmdContext):
    """Stop and re-start an instance with the same binary and IDB."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    log.debug("cmd_restart: resolving instance")
    iid, info = resolve_instance(args, config)
    if not iid:
        return
    binary_path = info.get("path")
    idb_path = info.get("idb_path")
    if not binary_path:
        _log_err("Cannot restart: binary path unknown")
        return
    # Derive idb_dir from idb_path
    idb_dir = os.path.dirname(idb_path) if idb_path else None

    # Stop — build args with .id for cmd_stop
    _log_info(f"Stopping {iid}...")
    import argparse as _ap
    stop_args = _ap.Namespace(id=iid)
    cmd_stop(CmdContext(args=stop_args, config=config, config_path=config_path))
    time.sleep(1)

    # Verify stop succeeded — prevent two processes running
    pid = info.get("pid")
    if pid and _is_process_alive(pid):
        _force_kill(iid, pid, info.get("pid_create_time"))
        log.warning("cmd_restart: old PID %d still alive after stop, force-killed", pid)
        time.sleep(0.5)

    # Re-start with same binary and idb_dir
    class _RestartArgs:
        pass
    new_args = _RestartArgs()
    new_args.binary = binary_path
    new_args.idb_dir = idb_dir
    new_args.force = False
    new_args.fresh = _opt(args, 'fresh', False)
    new_args.arch = None
    new_args.binary_hint = None
    new_args.instance = None
    new_args.json_output = False
    new_args.config = None
    new_ctx = CmdContext(args=new_args, config=config, config_path=config_path)
    cmd_start(new_ctx)


def cmd_wait(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    iid = args.id
    log.debug("cmd_wait: id=%s timeout=%s", iid, _opt(args, 'timeout', 300))
    timeout = _opt(args, 'timeout', 300)
    poll = config.get("analysis", {}).get("wait_poll_interval", 1.0)
    deadline = time.time() + timeout
    state = "unknown"
    while time.time() < deadline:
        info = load_registry().get(iid)
        if not info:
            _log_err(f"Instance {iid} not found")
            return
        state = info.get("state", "unknown")
        port = info.get("port")
        if state in ("initializing", "analyzing"):
            remaining = max(0, int(deadline - time.time()))
            _log_info(f"{state}... ({remaining}s remaining)")
            time.sleep(poll)
            continue
        if state == "ready" and port:
            resp = post_rpc(config, port, "ping", iid)
            if resp.get("result", {}).get("state") == "ready":
                _log_ok("ready")
                return
        if state == "error":
            _log_err(f"Analysis failed. Check: ida_cli.py logs {iid}")
            return
        time.sleep(poll)
    _log_err(f"Timeout ({timeout}s). Current state: {state}")


def cmd_list(ctx: CmdContext):
    log.debug("cmd_list: loading registry")
    args, config = ctx.args, ctx.config
    try:
        with _registry_locked():
            registry = load_registry()
            cleanup_stale(registry, config.get("analysis", {}).get("stale_threshold", 86400))
    except RuntimeError:
        _log_err("Could not acquire registry lock")
        return
    log.debug("cmd_list: found %d instances", len(registry))
    if not registry:
        _log_info("No active instances")
        return
    if _opt(args, 'json_output', False):
        out = {}
        for iid, info in registry.items():
            out[iid] = {
                "state": info.get("state", "unknown"),
                "binary": info.get("binary", "?"),
                "port": info.get("port"),
                "pid": info.get("pid"),
                "idb": info.get("idb_path"),
            }
        print(json.dumps(out, indent=2))
        return
    for iid, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        print(f"  {iid}  {state:<12}  {binary}  port={port}")


def cmd_status(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    iid = _opt(args, 'id')
    log.debug("cmd_status: id=%s", iid)
    if not iid:
        # Try resolving from -b hint or single active instance
        resolved_id, resolved_info = resolve_instance(args, config)
        if resolved_id:
            iid = resolved_id
        else:
            cmd_list(ctx)
            return
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
        return
    if info.get("state") == "ready" and info.get("port"):
        resp = post_rpc(config, info["port"], "status", iid)
        if "result" in resp:
            r = resp["result"]
            print(f"  ID:         {iid}")
            print(f"  State:      {r.get('state')}")
            print(f"  Binary:     {r.get('binary')}")
            print(f"  Functions:  {r.get('func_count')}")
            print(f"  Decompiler: {r.get('decompiler_available')}")
            print(f"  IDA:        {r.get('ida_version')}")
            print(f"  Uptime:     {r.get('uptime')}s")
            return
    for k, v in info.items():
        print(f"  {k}: {v}")


def cmd_logs(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    log.debug("cmd_logs: resolving instance")
    iid, info = resolve_instance(args, config)
    if not iid:
        return
    log_path = info.get("log_path")
    log.debug("cmd_logs: log_path=%s", log_path)
    if not log_path or not os.path.exists(log_path):
        log.warning("cmd_logs: log file not found: %s", log_path)
        _log_err(f"Log file not found: {log_path}")
        return
    if _opt(args, 'follow', False):
        try:
            with open(log_path, encoding='utf-8') as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        print(line, end='', flush=True)
                    else:
                        if not os.path.exists(log_path):
                            _log_info("Log file removed")
                            return
                        time.sleep(STOP_POLL_INTERVAL)
        except KeyboardInterrupt:
            pass
    else:
        tail = _opt(args, 'tail', 50)
        with open(log_path, encoding='utf-8') as f:
            lines = f.readlines()
        for line in lines[-tail:]:
            print(line, end='')


def cmd_cleanup(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    dry_run = _opt(args, 'dry_run', False)
    log.debug("cmd_cleanup: dry_run=%s", dry_run)
    registry = load_registry()
    active_ids = set(registry.keys())
    log_dir = config.get("paths", {}).get("log_dir", "")
    idb_dir = config.get("paths", {}).get("idb_dir", "")
    cutoff = time.time() - CLEANUP_AGE_SECONDS
    # Clean stale top-level log files (legacy .log format)
    for f in glob.glob(os.path.join(log_dir, "*.log*")):
        iid = os.path.basename(f).split(".")[0]
        if iid not in active_ids and os.path.getmtime(f) < cutoff:
            if dry_run:
                print(f"  [dry-run] Would delete: {f}")
            else:
                os.remove(f)
                print(f"  Deleted: {f}")
    # P7: Clean orphan instance logs (jsonl + stderr) in logs/ida/instances/
    instance_log_dir = os.path.join(log_dir, "ida", "instances")
    if os.path.isdir(instance_log_dir):
        for f in glob.glob(os.path.join(instance_log_dir, "*")):
            basename = os.path.basename(f)
            iid = basename.split(".")[0]
            if iid not in active_ids and os.path.getmtime(f) < cutoff:
                if dry_run:
                    print(f"  [dry-run] Would delete instance log: {f}")
                else:
                    try:
                        os.remove(f)
                        print(f"  Deleted instance log: {f}")
                    except OSError:
                        log.warning("cmd_cleanup: failed to delete instance log: %s", f)
    token_path = config.get("security", {}).get("auth_token_file", "")
    if os.path.exists(token_path):
        try:
            with _registry_locked():
                with open(token_path, encoding="utf-8") as fp:
                    lines = fp.readlines()
                cleaned = [l for l in lines if l.strip().split(":")[0] in active_ids]
                removed = len(lines) - len(cleaned)
                if removed > 0:
                    if dry_run:
                        print(f"  [dry-run] Would remove {removed} stale auth entries")
                    else:
                        with open(token_path, "w", encoding="utf-8") as fp:
                            fp.writelines(cleaned)
                        print(f"  Removed {removed} stale auth entries")
        except RuntimeError:
            log.warning("cmd_cleanup: could not acquire lock for auth token cleanup")
    for f in glob.glob(os.path.join(idb_dir, "*")):
        if f.endswith(".meta.json"):
            continue
        in_use = any(info.get("idb_path") == f for info in registry.values())
        if not in_use:
            print(f"  [info] Unused: {os.path.basename(f)}")
    # Kill orphaned IDA server processes not in registry
    active_pids = {info.get("pid") for info in registry.values() if info.get("pid")}
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmdline = proc.info.get("cmdline") or []
                cmd_str = " ".join(cmdline)
                if "ida_server" in cmd_str and proc.info["pid"] not in active_pids:
                    if dry_run:
                        print(f"  [dry-run] Would kill orphan PID {proc.info['pid']}: {cmd_str[:80]}")
                    else:
                        proc.kill()
                        print(f"  Killed orphan PID {proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        log.warning("cmd_cleanup: psutil not available, skipping orphan process cleanup")
    # Clean IDA temp files (.id0, .id1, .id2, .nam, .til) from instance IDB dirs
    _IDB_TEMP_EXTS = (".id0", ".id1", ".id2", ".nam", ".til")
    for idb_subdir in glob.glob(os.path.join(idb_dir, "*", "")):
        iid = os.path.basename(os.path.normpath(idb_subdir))
        if iid in active_ids:
            continue
        for tmp in os.listdir(idb_subdir):
            if any(tmp.endswith(ext) for ext in _IDB_TEMP_EXTS):
                tmp_path = os.path.join(idb_subdir, tmp)
                if dry_run:
                    print(f"  [dry-run] Would delete temp: {tmp_path}")
                else:
                    try:
                        os.remove(tmp_path)
                        print(f"  Deleted temp: {tmp_path}")
                    except OSError:
                        print(f"  [warn] Cannot delete (busy?): {tmp_path}")
    _log_ok("Cleanup done")
