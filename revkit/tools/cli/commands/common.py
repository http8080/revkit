"""Tier 1 commands -- shared start/list/stop/status/wait implementations."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ...core.instance import make_instance_id, resolve_instance, wait_for_start
from ...core.logging_setup import get_instance_log_path, get_instance_stderr_path
from ...core.output import log_err, log_info, log_ok, md_table_header
from ...core.process import detach_spawn
from ...core.registry import (
    cleanup_stale,
    get_registry_path,
    load_registry,
    register_instance,
    unregister_instance,
)
from ...core.logging_setup import log_lifecycle
from ...core.rpc import RpcError, post_rpc
from ...engines.base import CmdContext

log = logging.getLogger(__name__)


def _load_token_for_instance(config: dict, iid: str) -> str | None:
    """Read auth token for a given instance from the token file."""
    import os
    token_path = config.get("security", {}).get("auth_token_file", "")
    if not token_path or not os.path.exists(token_path):
        return None
    try:
        with open(token_path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[0] == iid:
                    return parts[2]
    except OSError:
        pass
    return None


def _wait_for_exit(pid: int, timeout: float = 30) -> bool:
    """Wait for a process to exit. Returns True if exited, False if force-killed.

    Polls process status every 1s. Force-kills process tree after timeout.
    """
    import time
    try:
        import psutil
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not proc.is_running():
                return True
            try:
                proc.wait(timeout=1)
                return True
            except psutil.TimeoutExpired:
                continue
        # timeout — force kill entire process tree (children first)
        log.warning("_wait_for_exit: PID %d still alive after %ds, force-killing process tree", pid, int(timeout))
        try:
            children = proc.children(recursive=True)
        except psutil.NoSuchProcess:
            return True
        for child in children:
            try:
                log.debug("_wait_for_exit: killing child PID %d", child.pid)
                child.kill()
            except psutil.NoSuchProcess:
                pass
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            pass
        return False
    except ImportError:
        import os
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return True
            time.sleep(1)
        # fallback force kill
        from ..core.process import force_kill
        force_kill(pid)
        return False


def cmd_start(args, config, engine):
    binary = str(Path(args.binary).resolve())
    if not Path(binary).exists():
        log_err(f"File not found: {binary}")
        return None
    instance_id = engine.make_instance_id(binary)
    reg_path = get_registry_path(engine.engine_name)
    log.debug("cmd_start: binary=%s iid=%s force=%s fresh=%s",
              binary, instance_id, getattr(args, 'force', False), getattr(args, 'fresh', False))

    # Check max_instances limit
    max_inst = config.get("analysis", {}).get("max_instances", 30)
    if max_inst is not None and max_inst >= 0:
        current = cleanup_stale(reg_path)
        if len(current) >= max_inst:
            log_err(f"Max instances reached ({max_inst}). Stop an instance first.")
            return None

    log_path = str(get_instance_log_path(engine.engine_name, instance_id))

    # IDA needs idb_path; JEB needs project_path
    extra = {}
    if engine.engine_name == "ida":
        idb_dir = config.get("paths", {}).get("idb_dir", "")
        if idb_dir:
            import os
            ext = ".i64"
            idb_name = os.path.splitext(os.path.basename(binary))[0] + ext
            extra["idb_path"] = os.path.join(idb_dir, instance_id, idb_name)
    elif engine.engine_name == "jeb":
        project_dir = config.get("paths", {}).get("project_dir", "")
        if project_dir:
            import os, glob as _glob, re as _re
            # Look for existing .jdb2 from a previous session with the same binary
            existing_jdb2 = None
            if not args.fresh:
                basename = os.path.splitext(os.path.basename(binary))[0].lower()
                clean = _re.sub(r"[^a-z0-9-]", "-", basename)
                clean = _re.sub(r"-+", "-", clean).strip("-")[:20].rstrip("-")
                os.makedirs(project_dir, exist_ok=True)
                candidates = [f for f in _glob.glob(os.path.join(project_dir, "*.jdb2"))
                              if os.path.basename(f).lower().startswith(clean + "_")]
                if candidates:
                    existing_jdb2 = max(candidates, key=os.path.getmtime)
            if existing_jdb2:
                # Rename to match current instance_id
                new_path = os.path.join(project_dir, f"{instance_id}.jdb2")
                try:
                    os.rename(existing_jdb2, new_path)
                    extra["project_path"] = os.path.splitext(new_path)[0]  # without .jdb2
                    log_info(f"Reusing saved project: {os.path.basename(existing_jdb2)}")
                except OSError:
                    extra["project_path"] = os.path.join(project_dir, instance_id)
            else:
                extra["project_path"] = os.path.join(project_dir, instance_id)

    entry = engine.build_initial_registry_entry(
        instance_id, binary,
        config_path=args.config,
        log_path=log_path,
        **extra,
    )

    spawn_cfg = engine.build_spawn_config(
        config, binary, instance_id,
        config_path=args.config,
        idb_path=entry.get("idb_path", ""),
        log_path=entry.get("log_path", ""),
        project_path=entry.get("project_path", ""),
        fresh=args.fresh,
        xmx=getattr(args, "xmx", None),
    )
    engine.pre_spawn(config, spawn_cfg, binary_path=binary)

    # Spawn FIRST, then register — prevents dangling entries on spawn failure
    pid = detach_spawn(spawn_cfg)
    entry["pid"] = pid
    register_instance(reg_path, entry)

    engine_cfg = config.get(engine.engine_name, {})
    server_type = engine_cfg.get("server_type", "")
    spawn_method = "java" if server_type == "java" else engine_cfg.get("spawn_method", "default")
    log_ok(f"Started {engine.engine_name} (id={instance_id}, pid={pid}, spawn={spawn_method})")
    log_lifecycle(engine.engine_name, "instance.start",
                  instance_id, binary=binary, pid=pid, spawn_method=spawn_method)

    return {"instance_id": instance_id, "pid": pid}


def cmd_list(args, config, engine):
    reg_path = get_registry_path(engine.engine_name)
    entries = cleanup_stale(reg_path)
    if not entries:
        log_info("No active instances.")
        return []

    print(md_table_header("ID", "State", "PID", "Port", "Binary"))
    for e in entries:
        print(f"| {e.get('id', '?')} | {e.get('state', '?')} | "
              f"{e.get('pid', '-')} | {e.get('port', '-')} | "
              f"{e.get('binary', '?')} |")
    return entries


def cmd_stop(args, config, engine):
    reg_path = get_registry_path(engine.engine_name)
    iid, info = resolve_instance(args, reg_path)
    if not iid:
        return None

    port = info.get("port")
    pid = info.get("pid")
    trace_id = getattr(args, "_trace_id", None)
    stop_timeout = config.get("analysis", {}).get("stop_timeout", 30)
    log.debug("cmd_stop: iid=%s port=%s pid=%s", iid, port, pid)
    if port:
        try:
            host = config.get("server", {}).get("host", "127.0.0.1")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            url = f"http://{host}:{port}/"
            token = _load_token_for_instance(config, iid)
            # IDA uses "save_db", JEB uses "save" — pick correct method
            save_method = "save_db" if engine.engine_name == "ida" else "save"
            log.debug("cmd_stop: sending %s RPC to %s", save_method, url)
            try:
                post_rpc(url, save_method, auth_token=token, trace_id=trace_id,
                         timeout=stop_timeout, retries=1)
                log_info(f"Database saved for {iid}")
            except RpcError as exc:
                log.warning("cmd_stop: save failed for %s: %s (proceeding to stop)", iid, exc)
            log.debug("cmd_stop: sending stop RPC")
            post_rpc(url, "stop", auth_token=token, trace_id=trace_id,
                     timeout=stop_timeout, retries=1)
        except RpcError as exc:
            log.warning("cmd_stop: RPC failed for %s: %s", iid, exc)

    # Wait for process to exit gracefully (save + close_database)
    if pid:
        log.debug("cmd_stop: waiting for PID %d to exit (timeout=%ds)", pid, stop_timeout)
        exited = _wait_for_exit(pid, timeout=stop_timeout)
        if not exited:
            log.warning("cmd_stop: PID %d did not exit gracefully, force-killed", pid)

    unregister_instance(reg_path, iid)
    log_ok(f"Stopped {iid}")
    log_lifecycle(engine.engine_name, "instance.stop", iid)
    return {"instance_id": iid}


def cmd_status(args, config, engine):
    reg_path = get_registry_path(engine.engine_name)
    iid, info = resolve_instance(args, reg_path)
    if not iid:
        return None
    log.debug("cmd_status: iid=%s state=%s", iid, info.get("state"))
    log_info(f"Instance: {iid}")
    for k, v in info.items():
        log_info(f"  {k}: {v}")

    # If server is ready, fetch live info via RPC
    port = info.get("port")
    state = info.get("state")
    trace_id = getattr(args, "_trace_id", None)
    if port and state == "ready":
        try:
            host = config.get("server", {}).get("host", "127.0.0.1")
            url = f"http://{host}:{port}/"
            token = _load_token_for_instance(config, iid)
            resp = post_rpc(url, "status", auth_token=token, trace_id=trace_id)
            rpc_status = resp.get("result") if isinstance(resp, dict) else None
            if rpc_status:
                log_info("  --- live server info ---")
                for k, v in rpc_status.items():
                    if k not in info:
                        log_info(f"  {k}: {v}")
                info["server_info"] = rpc_status
        except RpcError:
            pass

    return info


def cmd_wait(args, config, engine):
    import time as _time
    reg_path = get_registry_path(engine.engine_name)
    iid, info = resolve_instance(args, reg_path)
    if not iid:
        # Instance may not be registered yet (JEB wrapper startup delay).
        # Retry resolve for up to 30 seconds before giving up.
        deadline = _time.time() + 30
        while _time.time() < deadline:
            _time.sleep(2)
            iid, info = resolve_instance(args, reg_path)
            if iid:
                break
        if not iid:
            return None
    log.debug("cmd_wait: iid=%s timeout=%.1fs", iid, args.timeout)
    try:
        ok = wait_for_start(reg_path, iid, timeout=args.timeout)
    except KeyboardInterrupt:
        # Ctrl+C during wait → kill the waiting instance to prevent orphan
        pid = info.get("pid") if info else None
        if pid:
            from ..core.process import force_kill
            force_kill(pid)
            log.warning("cmd_wait: Ctrl+C — killed PID %d to prevent orphan", pid)
        log_err(f"Wait interrupted for {iid} — process killed")
        return {"instance_id": iid, "ready": False}
    if ok:
        log_ok(f"{iid} is ready")
    else:
        log.warning("cmd_wait: iid=%s did not reach ready state", iid)
    return {"instance_id": iid, "ready": ok}


TIER1_HANDLERS = {
    "start": cmd_start,
    "list": cmd_list,
    "stop": cmd_stop,
    "status": cmd_status,
    "wait": cmd_wait,
}
