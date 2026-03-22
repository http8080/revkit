"""Instance management commands -- init, check, start, stop, restart, etc."""

import json
import logging
import os
import sys
import time
import glob

from ..core import (
    _rpc_call, _log_ok, _log_err, _log_info, _log_warn,
    _opt, _truncate,
    _registry_locked, _force_kill, _cleanup_instance,
    _register_instance, _spawn_server, _wait_for_start,
    _get_launcher_name,
    load_registry, save_registry, cleanup_stale,
    make_instance_id, resolve_instance,
    post_rpc, psutil,
    STOP_WAIT_ITERATIONS, STOP_POLL_INTERVAL, STOP_RPC_TIMEOUT,
    CLEANUP_AGE_SECONDS,
)
from ...base import CmdContext
from ....core.logging_setup import log_lifecycle

log = logging.getLogger(__name__)


def _find_existing_jdb2(project_dir: str, binary_path: str):
    """Find an existing .jdb2 file for the same binary from a previous session.

    Searches by matching the binary base name prefix in .jdb2 filenames.
    Returns the path of the most recently modified match, or None.
    """
    basename = os.path.splitext(os.path.basename(binary_path))[0].lower()
    # Sanitize same way as make_instance_id
    import re
    clean = re.sub(r"[^a-z0-9-]", "-", basename)
    clean = re.sub(r"-+", "-", clean).strip("-")
    if len(clean) > 20:
        clean = clean[:20].rstrip("-")

    candidates = []
    for f in glob.glob(os.path.join(project_dir, "*.jdb2")):
        fname = os.path.basename(f).lower()
        if fname.startswith(clean + "_"):
            candidates.append(f)

    if not candidates:
        return None
    # Return the most recently modified .jdb2
    return max(candidates, key=os.path.getmtime)


def _lookup_instance(iid):
    """Look up instance by ID from registry. Returns info or None (with error log)."""
    info = load_registry().get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
    return info


def _SimpleArgs(**kwargs):
    """Create a minimal args namespace for internal command reuse."""
    import argparse
    defaults = {"binary_hint": None, "instance": None,
                "json_output": False, "config": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def cmd_init(ctx: CmdContext):
    """Create data directories (projects, logs, registry parent)."""
    log.debug("cmd_init: creating data directories")
    config = ctx.config
    jeb_reg = config.get("jeb", {}).get("registry", "~/.revkit/jeb/registry.json")
    jeb_reg = os.path.expanduser(jeb_reg)
    _paths = config.get("paths", {})
    dirs = [
        _paths.get("project_dir", ""),
        _paths.get("log_dir", ""),
        os.path.dirname(jeb_reg),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        _log_ok(d)
    _log_ok("Init complete")


def cmd_check(ctx: CmdContext):
    """Verify environment: Python version, JEB install, dependencies."""
    log.debug("cmd_check: verifying environment")
    config = ctx.config
    issues = []

    def _check(label, ok, fail_msg=None, detail=""):
        status = "OK" if ok else (detail or "NOT FOUND")
        print(f"  {label}: {status}")
        if not ok and fail_msg:
            issues.append(fail_msg)

    print(f"  Python: {sys.version.split()[0]}")
    if sys.version_info < (3, 10):
        issues.append("Python 3.10+ required")

    jeb_dir = config.get("jeb", {}).get("install_dir", "")
    _check(f"JEB dir ({jeb_dir})", os.path.isdir(jeb_dir), f"JEB dir not found: {jeb_dir}")

    launcher = os.path.join(jeb_dir, _get_launcher_name())
    _check(f"Launcher ({os.path.basename(launcher)})", os.path.isfile(launcher),
           f"Launcher not found: {launcher}")

    runner = os.path.join(jeb_dir, "JebScriptRunner.class")
    _check("Runner", os.path.isfile(runner),
           "JebScriptRunner.class not found (run: jeb-cli gen-runner)")

    spawn_method = config["jeb"].get("spawn_method", "wrapper")
    jvmopt_path = os.path.join(jeb_dir, "jvmopt.txt")
    jvmopt_ok = os.path.isfile(jvmopt_path)
    if spawn_method == "bat":
        _check("jvmopt.txt", jvmopt_ok, "jvmopt.txt not found (required for bat spawn method)")
    else:
        print(f"  jvmopt.txt: {'OK' if jvmopt_ok else 'optional'}")
    print(f"  Spawn: {spawn_method}")

    java_home = config["jeb"].get("java_home", "")
    jvm_opts = config["jeb"].get("jvm_opts", [])
    if spawn_method == "wrapper":
        print(f"  Java:  {java_home if java_home else '(system PATH)'}")
        if jvm_opts:
            print(f"  JVM:   {' '.join(jvm_opts)}")
    else:
        if java_home or jvm_opts:
            print(f"  Note:  java_home/jvm_opts ignored in bat mode (uses jvmopt.txt)")

    for mod_name, mod in [("requests", None), ("psutil", psutil)]:
        try:
            if mod is None:
                import requests as mod
            print(f"  {mod_name}: {getattr(mod, '__version__', 'found')}")
        except ImportError:
            issues.append(f"{mod_name} not installed")
            print(f"  {mod_name}: NOT FOUND")

    if issues:
        print(f"\n[-] {len(issues)} issue(s):")
        for i in issues:
            print(f"  - {i}")
    else:
        print("\n[+] All checks passed")


def cmd_start(ctx: CmdContext):
    """Start a new JEB analysis instance."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    binary_path = os.path.normcase(os.path.abspath(args.binary))
    log.debug("cmd_start: binary=%s", binary_path)
    # #6: if directory, auto-merge split APKs then start
    if os.path.isdir(binary_path):
        from .tooling import cmd_merge  # lazy import to avoid circular
        _log_info(f"Directory detected, auto-merging split APKs...")
        merge_args = _SimpleArgs(
            input=binary_path, out=None, start=False,
            xmx=_opt(args, 'xmx'))
        merge_ctx = CmdContext(args=merge_args, config=config, config_path=config_path)
        merged = cmd_merge(merge_ctx)
        if not merged or not os.path.isfile(merged):
            _log_err("Auto-merge failed")
            return
        binary_path = os.path.normcase(os.path.abspath(merged))
        _log_ok(f"Merged: {os.path.basename(binary_path)}")
    if not os.path.isfile(binary_path):
        _log_err(f"Binary not found: {binary_path}")
        return

    instance_id = make_instance_id(binary_path)
    force = _opt(args, 'force', False)
    fresh = _opt(args, 'fresh', False)
    project_dir_override = _opt(args, 'project_dir')

    # Determine project path — reuse existing .jdb2 for same binary if available
    project_dir = project_dir_override or config.get("paths", {}).get("project_dir", "")
    os.makedirs(project_dir, exist_ok=True)
    project_path = os.path.join(project_dir, f"{instance_id}.jdb2")

    if not fresh and not force:
        # Search for existing .jdb2 from a previous session with the same binary
        existing_jdb2 = _find_existing_jdb2(project_dir, binary_path)
        if existing_jdb2 and existing_jdb2 != project_path:
            # Rename to match current instance_id
            new_path = os.path.join(project_dir, f"{instance_id}.jdb2")
            try:
                os.rename(existing_jdb2, new_path)
                project_path = new_path
                _log_info(f"Reusing saved project: {os.path.basename(existing_jdb2)}")
            except OSError:
                _log_info(f"Could not reuse {existing_jdb2}, starting fresh")
        elif os.path.exists(project_path):
            _log_info(f"Reusing existing project: {project_path}")

    log_path = os.path.join(config.get("paths", {}).get("log_dir", ""), f"{instance_id}.log")

    if not _register_instance(config, instance_id, binary_path,
                               project_path, log_path, force):
        return

    xmx = _opt(args, 'xmx')
    proc = _spawn_server(config, config_path, binary_path, instance_id,
                         project_path, log_path, fresh, xmx=xmx)

    # Immediately record PID so cleanup_stale can track this process
    try:
        with _registry_locked():
            reg = load_registry()
            if instance_id in reg:
                reg[instance_id]["pid"] = proc.pid
                save_registry(reg)
    except RuntimeError:
        log.warning("cmd_start: failed to acquire registry lock for PID update")

    state = _wait_for_start(config, instance_id)

    spawn_method = config.get("jeb", {}).get("spawn_method", "wrapper")
    log_lifecycle("jeb", "instance.start", instance_id,
                  binary=os.path.basename(binary_path), pid=proc.pid,
                  spawn_method=spawn_method)
    _log_ok(f"Instance started: {instance_id} (spawn={spawn_method})")
    if state == "error":
        _log_err(f"Analysis failed. Check: jeb-cli logs {instance_id}")
    elif state in ("initializing", "analyzing"):
        if _opt(args, 'wait', False):
            _log_info(f"Waiting for analysis to complete...")
            cmd_wait_internal(config, instance_id)
        else:
            _log_info(f"Still {state}. Use: jeb-cli wait {instance_id}")
    # #1: show port in start output (read after wait to get updated port)
    info = load_registry().get(instance_id, {})
    port = info.get("port", "-")
    final_state = info.get("state", state)
    print(f"    Binary:   {os.path.basename(binary_path)}")
    print(f"    Project:  {project_path}")
    print(f"    Log:      {log_path}")
    print(f"    State:    {final_state}")
    print(f"    PID:      {proc.pid}")
    if port and port != "-":
        print(f"    Port:     {port}")
    java_home = config.get("jeb", {}).get("java_home", "")
    jvm_opts = config.get("jeb", {}).get("jvm_opts", [])
    if spawn_method == "wrapper":
        print(f"    Java:     {java_home if java_home else '(system PATH)'}")
        if jvm_opts:
            print(f"    JVM opts: {' '.join(jvm_opts)}")

    log.debug("cmd_start: instance %s started, state=%s", instance_id, final_state)
    return instance_id


def cmd_stop(ctx: CmdContext):
    """Stop a running JEB instance."""
    args, config = ctx.args, ctx.config
    iid = args.id
    log.debug("cmd_stop: id=%s", iid)
    info = _lookup_instance(iid)
    if not info:
        return
    port = info.get("port")
    pid = info.get("pid")

    # Try graceful RPC stop
    if port:
        try:
            post_rpc(config, port, "stop", iid, timeout=STOP_RPC_TIMEOUT)
            for _ in range(STOP_WAIT_ITERATIONS):
                time.sleep(STOP_POLL_INTERVAL)
                if iid not in load_registry():
                    _log_ok(f"Instance {iid} stopped normally")
                    return
        except Exception as _e:
            log.warning("cmd_stop: graceful RPC stop failed for %s: %s", iid, _e)

    # Force kill
    if pid:
        _force_kill(iid, pid, info.get("pid_create_time"))

    # Clean up registry and auth token
    _cleanup_instance(config, iid)
    _log_ok(f"Instance {iid} stopped")


def cmd_restart(ctx: CmdContext):
    """Stop and re-start an instance with the same binary."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    iid, info = resolve_instance(args, config)
    log.debug("cmd_restart: id=%s", iid)
    if not iid:
        return
    binary_path = info.get("path")
    if not binary_path:
        _log_err("Cannot restart: binary path unknown")
        return
    project_dir = os.path.dirname(info.get("project_path", "")) or None

    _log_info(f"Stopping {iid}...")
    stop_args = _SimpleArgs(id=iid)
    cmd_stop(CmdContext(args=stop_args, config=config, config_path=config_path))
    time.sleep(1)

    # Verify stop succeeded — prevent two processes running
    pid = info.get("pid")
    if pid:
        from ....core.instance import is_process_alive as _alive
        if _alive(pid):
            _force_kill(iid, pid, info.get("pid_create_time"))
            log.warning("cmd_restart: old PID %d still alive after stop, force-killed", pid)
            time.sleep(0.5)

    # Re-start with same binary
    # #2: propagate --wait flag
    new_args = _SimpleArgs(
        binary=binary_path, project_dir=project_dir,
        force=False, fresh=_opt(args, 'fresh', False),
        wait=_opt(args, 'wait', False), xmx=_opt(args, 'xmx'))
    cmd_start(CmdContext(args=new_args, config=config, config_path=config_path))


def cmd_wait_internal(config, iid, timeout=300):
    """Shared wait logic — blocks until instance is ready or timeout."""
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
            _log_err(f"Analysis failed. Check: jeb-cli logs {iid}")
            return
        time.sleep(poll)
    _log_err(f"Timeout ({timeout}s). Current state: {state}")


def cmd_wait(ctx: CmdContext):
    """Wait for an instance to reach 'ready' state."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_wait: id=%s timeout=%s", args.id, _opt(args, 'timeout', 300))
    cmd_wait_internal(config, args.id, _opt(args, 'timeout', 300))


def cmd_list(ctx: CmdContext):
    """List active JEB instances."""
    log.debug("cmd_list: listing instances")
    args, config = ctx.args, ctx.config
    try:
        with _registry_locked():
            registry = load_registry()
            cleanup_stale(registry, config.get("analysis", {}).get("stale_threshold", 86400))
    except RuntimeError:
        _log_err("Could not acquire registry lock")
        return
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
                "project": info.get("project_path"),
            }
        print(json.dumps(out, indent=2))
        return
    for iid, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        # #3: uptime + memory
        uptime_str = ""
        started = info.get("started")
        if started:
            elapsed = int(time.time() - started)
            if elapsed >= 3600:
                uptime_str = f"{elapsed // 3600}h{(elapsed % 3600) // 60}m"
            elif elapsed >= 60:
                uptime_str = f"{elapsed // 60}m{elapsed % 60}s"
            else:
                uptime_str = f"{elapsed}s"
        mem_str = ""
        pid = info.get("pid")
        if pid and psutil:
            try:
                proc = psutil.Process(pid)
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                mem_str = f"{mem_mb:.0f}MB"
            except Exception:
                log.warning("cmd_list: failed to get memory for pid=%s", pid)
        extras = f"  port={port}"
        if uptime_str:
            extras += f"  up={uptime_str}"
        if mem_str:
            extras += f"  mem={mem_str}"
        print(f"  {iid}  {state:<12}  {binary}{extras}")


def cmd_status(ctx: CmdContext):
    """Show detailed status for an instance."""
    args, config = ctx.args, ctx.config
    iid = _opt(args, 'id')
    log.debug("cmd_status: id=%s", iid)
    if not iid:
        resolved_id, resolved_info = resolve_instance(args, config)
        if resolved_id:
            iid = resolved_id
        else:
            cmd_list(ctx)
            return
    info = _lookup_instance(iid)
    if not info:
        return
    if info.get("state") == "ready" and info.get("port"):
        resp = post_rpc(config, info["port"], "status", iid)
        if "result" in resp:
            r = resp["result"]
            fields = [("ID", iid), ("State", r.get("state", "?")),
                      ("Binary", r.get("binary", "?")),
                      ("Classes", r.get("class_count", "?")),
                      ("Methods", r.get("method_count", "?")),
                      ("Dex count", r.get("dex_count", "?")),
                      ("JEB version", r.get("jeb_version", "?")),
                      ("Uptime", f"{r.get('uptime')}s")]
            for label, val in fields:
                print(f"  {label + ':':<13} {val}")
            return
    for k, v in info.items():
        print(f"  {k}: {v}")


def cmd_logs(ctx: CmdContext):
    """Show log output for an instance."""
    args, config = ctx.args, ctx.config
    iid, info = resolve_instance(args, config)
    log.debug("cmd_logs: id=%s follow=%s", iid, _opt(args, 'follow', False))
    if not iid:
        return
    log_path = info.get("log_path")
    if not log_path or not os.path.exists(log_path):
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
                        time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    else:
        tail = _opt(args, 'tail', 50)
        with open(log_path, encoding='utf-8') as f:
            lines = f.readlines()
        for line in lines[-tail:]:
            print(line, end='')


def cmd_cleanup(ctx: CmdContext):
    """Clean up stale logs, tokens, and orphaned projects."""
    args, config = ctx.args, ctx.config
    dry_run = _opt(args, 'dry_run', False)
    log.debug("cmd_cleanup: dry_run=%s all=%s", dry_run, _opt(args, 'all', False))
    # #4: --all flag: force stop and clean all instances
    if _opt(args, 'all', False):
        registry = load_registry()
        if not registry:
            _log_info("No instances to clean")
        else:
            for iid in list(registry.keys()):
                info = registry[iid]
                pid = info.get("pid")
                if pid:
                    if dry_run:
                        print(f"  [dry-run] Would kill instance {iid} (pid={pid})")
                    else:
                        _force_kill(iid, pid, info.get("pid_create_time"))
                        _cleanup_instance(config, iid)
                        print(f"  Stopped: {iid}")
                else:
                    if not dry_run:
                        _cleanup_instance(config, iid)
                        print(f"  Removed: {iid}")
        _log_ok("All instances cleaned")
        return

    registry = load_registry()

    # Remove stale registry entries via shared cleanup logic
    before = set(registry.keys())
    cleanup_stale(registry, config.get("analysis", {}).get("stale_threshold", 86400))
    removed = before - set(registry.keys())
    for iid in removed:
        print(f"  Removed stale instance: {iid}")

    active_ids = set(registry.keys())
    log_dir = config.get("paths", {}).get("log_dir", "")
    project_dir = config.get("paths", {}).get("project_dir", "")
    cutoff = time.time() - CLEANUP_AGE_SECONDS

    # Clean old top-level log files (legacy .log format)
    for f in glob.glob(os.path.join(log_dir, "*.log*")):
        iid = os.path.basename(f).split(".")[0]
        if iid not in active_ids and os.path.getmtime(f) < cutoff:
            if dry_run:
                print(f"  [dry-run] Would delete: {f}")
            else:
                os.remove(f)
                print(f"  Deleted: {f}")
    # P7: Clean orphan instance logs (jsonl + stderr) in logs/jeb/instances/
    instance_log_dir = os.path.join(log_dir, "jeb", "instances")
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
                    except OSError as _e:
                        log.warning("cmd_cleanup: failed to delete %s: %s", f, _e)

    # Clean stale auth tokens
    token_path = config.get("security", {}).get("auth_token_file", "")
    if os.path.exists(token_path):
        try:
            with _registry_locked():
                with open(token_path, encoding="utf-8") as fp:
                    lines = fp.readlines()
                cleaned = [l for l in lines if l.strip().split(":")[0] in active_ids]
                stale_count = len(lines) - len(cleaned)
                if stale_count > 0:
                    if dry_run:
                        print(f"  [dry-run] Would remove {stale_count} stale auth entries")
                    else:
                        with open(token_path, "w", encoding="utf-8") as fp:
                            fp.writelines(cleaned)
                        print(f"  Removed {stale_count} stale auth entries")
        except RuntimeError:
            log.warning("cmd_cleanup: failed to acquire lock for auth token cleanup")

    # Clean unused project files (.jdb2)
    if os.path.isdir(project_dir):
        for f in glob.glob(os.path.join(project_dir, "*")):
            if f.endswith(".meta.json"):
                continue
            in_use = any(info.get("project_path") == f for info in registry.values())
            if not in_use:
                if dry_run:
                    print(f"  [dry-run] Would delete unused project: {os.path.basename(f)}")
                else:
                    try:
                        os.remove(f)
                        print(f"  Deleted unused project: {os.path.basename(f)}")
                    except OSError as _e:
                        log.warning("cmd_cleanup: failed to delete %s: %s", f, _e)

    _log_ok("Cleanup done")


def cmd_save(ctx: CmdContext):
    """Save the current JEB project database."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_save: saving project")
    r = _rpc_call(args, config, "save_project")
    if r:
        log.debug("cmd_save: saved to %s", r.get('project_path', ''))
        _log_ok(f"Project saved: {r.get('project_path', '')}")
    else:
        log.warning("cmd_save: RPC returned None")
