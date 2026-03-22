"""revkit gateway — HTTP request router.

Routes API requests to appropriate handlers.
RPC proxy forwards JSON-RPC to engine servers with Host header rewriting.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from typing import Any

from .upload import UploadError, parse_multipart

log = logging.getLogger(__name__)

ROUTE_PATTERNS: list[tuple[str, str, str]] = [
    ("GET",    r"^/api/v1/health$",                      "handle_health"),
    ("GET",    r"^/api/v1/instances$",                    "handle_list_instances"),
    ("POST",   r"^/api/v1/instances/(?P<id>[^/]+)/rpc$",  "handle_rpc_proxy"),
    ("DELETE", r"^/api/v1/instances/(?P<id>[^/]+)$",      "handle_delete_instance"),
    ("POST",   r"^/api/v1/engines/(?P<engine>[^/]+)/start$", "handle_start_engine"),
    ("POST",   r"^/api/v1/upload$",                       "handle_upload"),
    ("GET",    r"^/api/v1/upload-progress/(?P<id>[^/]+)$", "handle_upload_progress"),
    # Gateway management endpoints
    ("GET",    r"^/api/v1/gateway/info$",                 "handle_gateway_info"),
    ("GET",    r"^/api/v1/gateway/config$",               "handle_gateway_config"),
    ("POST",   r"^/api/v1/gateway/config$",               "handle_gateway_config_set"),
    ("POST",   r"^/api/v1/gateway/stop-all$",             "handle_stop_all"),
    ("GET",    r"^/api/v1/gateway/uploads$",              "handle_gateway_uploads"),
    ("DELETE", r"^/api/v1/gateway/uploads$",              "handle_gateway_uploads_clean"),
    ("GET",    r"^/api/v1/gateway/audit$",                "handle_gateway_audit"),
    ("GET",    r"^/api/v1/gateway/system$",               "handle_gateway_system"),
    ("GET",    r"^/api/v1/gateway/disk$",                 "handle_gateway_disk"),
    ("POST",   r"^/api/v1/gateway/cleanup$",              "handle_gateway_cleanup"),
    ("POST",   r"^/api/v1/gateway/rotate-key$",           "handle_gateway_rotate_key"),
    ("POST",   r"^/api/v1/gateway/allow-ip$",             "handle_gateway_allow_ip"),
    ("GET",    r"^/api/v1/gateway/connections$",           "handle_gateway_connections"),
    ("GET",    r"^/api/v1/gateway/download/(?P<id>[^/]+)$", "handle_gateway_download"),
    ("GET",    r"^/api/v1/instances/(?P<id>[^/]+)/logs$", "handle_instance_logs"),
    ("GET",    r"^/api/v1/instances/(?P<id>[^/]+)/progress$", "handle_instance_progress"),
]

COMPILED_ROUTES: list[tuple[str, re.Pattern, str]] = [
    (method, re.compile(pattern), handler_name)
    for method, pattern, handler_name in ROUTE_PATTERNS
]


def route_request(handler: BaseHTTPRequestHandler, gw_config: dict) -> None:
    """Match request path against routes and dispatch."""
    method = handler.command
    path = handler.path.split("?")[0]
    log.debug("route_request: %s %s", method, path)

    for route_method, pattern, handler_name in COMPILED_ROUTES:
        if method != route_method:
            continue
        match = pattern.match(path)
        if match:
            log.debug("route_request: matched -> %s", handler_name)
            handler_func = globals().get(handler_name)
            if handler_func:
                handler_func(handler, gw_config, match)
                # Log connection for /connections endpoint
                client_ip = handler.client_address[0]
                status = getattr(handler, '_response_status', 200)
                _log_connection(client_ip, method, path, status)
                return

    log.debug("route_request: no match for %s %s", method, path)
    _send_json(handler, 404, {"error": "Not found", "path": path})
    client_ip = handler.client_address[0]
    _log_connection(client_ip, method, path, 404)


def handle_health(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/health — Gateway health check."""
    _send_json(handler, 200, {
        "status": "ok",
        "service": "revkit-gateway",
        "timestamp": time.time(),
    })


def handle_list_instances(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/instances — List all engine instances from registry."""
    from ..core.registry import get_registry_path, load_registry, cleanup_stale

    instances = []
    for engine_name in ("ida", "jeb"):
        reg_path = get_registry_path(engine_name)
        entries = cleanup_stale(reg_path)
        for entry in entries:
            # L17: copy to avoid mutating registry in-memory
            instances.append({**entry, "engine": engine_name})

    _send_json(handler, 200, {"instances": instances})


def handle_rpc_proxy(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/instances/{id}/rpc — Forward JSON-RPC to engine server."""
    instance_id = match.group("id")
    log.debug("handle_rpc_proxy: iid=%s", instance_id)
    instance = _find_instance(instance_id)
    if not instance:
        log.debug("handle_rpc_proxy: instance %s not found", instance_id)
        _send_json(handler, 404, {"error": f"Instance '{instance_id}' not found"})
        return

    port = instance.get("port")
    if not port:
        log.warning("handle_rpc_proxy: instance %s has no port", instance_id)
        _send_json(handler, 502, {"error": "Instance has no port assigned"})
        return

    # H10: validate Content-Length
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
    except (ValueError, TypeError):
        _send_json(handler, 400, {"error": "Invalid Content-Length header"})
        return
    max_rpc_body = 10 * 1024 * 1024  # 10MB
    if content_length < 0 or content_length > max_rpc_body:
        _send_json(handler, 413, {"error": f"Content-Length out of range (max {max_rpc_body})"})
        return

    body = handler.rfile.read(content_length) if content_length > 0 else b""

    gw_timeout = gw_config.get("request_timeout", 60) + 5
    rpc_method_name = None
    if body:
        try:
            rpc_body = json.loads(body)
            rpc_method_name = rpc_body.get("method")
            if isinstance(rpc_body.get("params"), dict):
                if rpc_body["params"].get("is_batch"):
                    gw_timeout = gw_config.get("batch_timeout", 300) + 5
        except (json.JSONDecodeError, AttributeError):
            pass

    # H3: block exec via gateway unless explicitly enabled
    if rpc_method_name == "exec" and not gw_config.get("exec_enabled", False):
        _send_json(handler, 403, {"error": "exec is disabled on gateway (set gateway.exec_enabled=true)"})
        return

    target_url = f"http://127.0.0.1:{port}/"

    headers = {
        "Content-Type": "application/json",
        "Host": f"127.0.0.1:{port}",
        "X-Forwarded-Host": handler.headers.get("Host", ""),
    }
    # H4: resolve auth token from registry or auth_tokens.json
    auth_token = _resolve_auth_token(instance_id, instance, gw_config)
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        req = urllib.request.Request(
            target_url, data=body, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=gw_timeout) as resp:
            resp_body = resp.read()
            handler.send_response(resp.status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(resp_body)))
            handler.end_headers()
            handler.wfile.write(resp_body)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        log.warning("handle_rpc_proxy: HTTP error %d from %s: %s", e.code, target_url, error_body[:200])
        _send_json(handler, e.code, {"error": error_body})
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("handle_rpc_proxy: engine unreachable at %s: %s", target_url, e)
        _send_json(handler, 502, {
            "error": "Engine server unreachable",
            "detail": str(e),
        })


def handle_delete_instance(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """DELETE /api/v1/instances/{id} — Stop and unregister an instance."""
    from ..core.registry import get_registry_path, unregister_instance

    instance_id = match.group("id")
    # M2: try to stop process before unregistering
    instance = _find_instance(instance_id)
    if instance:
        if instance.get("port"):
            try:
                _rpc_to_instance(instance, "save_db", gw_config=gw_config)
            except Exception:
                pass
            try:
                _rpc_to_instance(instance, "stop", gw_config=gw_config)
            except Exception:
                pass
        # Force-kill process if still alive after RPC stop (non-blocking)
        pid = instance.get("pid")
        if pid:
            from ..core.instance import is_process_alive
            if is_process_alive(pid):
                import threading
                def _deferred_kill(p, name):
                    import time as _t
                    _t.sleep(0.5)
                    if is_process_alive(p):
                        from ..core.process import force_kill
                        force_kill(p)
                        log.info("handle_delete_instance: deferred force-kill PID %d for %s", p, name)
                threading.Thread(target=_deferred_kill, args=(pid, instance_id), daemon=True).start()

    for engine_name in ("ida", "jeb"):
        reg_path = get_registry_path(engine_name)
        if unregister_instance(reg_path, instance_id):
            _send_json(handler, 200, {"deleted": instance_id})
            return

    _send_json(handler, 404, {"error": f"Instance '{instance_id}' not found"})


def handle_start_engine(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/engines/{engine}/start — Start an engine instance."""
    engine_name = match.group("engine")
    if engine_name not in ("ida", "jeb"):
        _send_json(handler, 400, {"error": f"Unknown engine: {engine_name}"})
        return

    content_length = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(content_length) if content_length > 0 else b"{}"
    try:
        params = json.loads(body)
    except json.JSONDecodeError:
        _send_json(handler, 400, {"error": "Invalid JSON body"})
        return

    file_id = params.get("file_id")
    if not file_id:
        _send_json(handler, 400, {"error": "file_id is required"})
        return

    # Resolve uploaded file path
    from .upload import get_upload_dir
    upload_dir = get_upload_dir(gw_config)
    uploaded_path = upload_dir / file_id
    if not uploaded_path.exists():
        _send_json(handler, 404, {"error": f"Uploaded file not found: {file_id}"})
        return

    # Restore original filename for IDB/project naming (basename only — prevent path traversal)
    original_name = os.path.basename(params.get("original_name", file_id))
    target_path = upload_dir / original_name
    if not target_path.exists() and uploaded_path.exists():
        import shutil
        shutil.copy2(str(uploaded_path), str(target_path))

    # Start engine instance via CLI
    import subprocess
    cmd = [sys.executable, "-m", "revkit.tools.cli.main", engine_name, "start",
           str(target_path)]
    # H2: pass start flags
    if params.get("fresh"):
        cmd.append("--fresh")
    if params.get("force"):
        cmd.append("--force")
    if params.get("xmx"):
        cmd.extend(["--xmx", str(params["xmx"])])

    # H6: use configurable timeout
    start_timeout = gw_config.get("request_timeout", 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=start_timeout)
        output = result.stdout.strip()

        # Extract instance_id from "id=xxxx" in output
        iid_match = re.search(r"id=(\S+?)[\s,)]", output)
        instance_id = iid_match.group(1) if iid_match else None

        if result.returncode == 0 and instance_id:
            # M14: cleanup uploaded file after successful start
            from .upload import cleanup_upload
            cleanup_upload(file_id, gw_config)
            _send_json(handler, 200, {
                "instance_id": instance_id,
                "engine": engine_name,
                "file_id": file_id,
                "output": output,
            })
        else:
            _send_json(handler, 500, {
                "error": "Engine start failed",
                "output": output,
                "stderr": result.stderr.strip(),
            })
    except subprocess.TimeoutExpired:
        # Kill any engine process that may have been started before timeout
        try:
            from ..core.registry import get_registry_path, cleanup_stale
            reg_path = get_registry_path(engine_name)
            entries = cleanup_stale(reg_path)
            # Find and kill the most recently started instance
            for entry in reversed(entries):
                pid = entry.get("pid")
                if pid:
                    from ..core.process import force_kill
                    force_kill(pid)
                    log.warning("handle_start_engine: killed orphan PID %d after timeout", pid)
                    break
        except Exception:
            pass
        _send_json(handler, 504, {"error": f"Engine start timed out ({start_timeout}s)"})


def handle_upload(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/upload — Upload a binary file."""
    try:
        result = parse_multipart(handler, gw_config)
        _send_json(handler, 200, result)
    except UploadError as e:
        _send_json(handler, e.status, {"error": e.message})


def handle_upload_progress(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/upload-progress/{id} — Upload progress polling (G5)."""
    file_id = match.group("id")
    _send_json(handler, 200, {
        "file_id": file_id,
        "status": "unknown",
        "message": "Progress tracking not yet implemented",
    })


# ──────────────────────────────────────────────────────────
# Gateway Management Handlers
# ──────────────────────────────────────────────────────────

# Track connections for /connections endpoint (thread-safe deque)
import collections as _collections
_connection_log: _collections.deque = _collections.deque(maxlen=500)
_gateway_start_time = time.time()


def _log_connection(client_ip: str, method: str, path: str, status: int):
    """Record connection for /connections endpoint (thread-safe via deque)."""
    _connection_log.append({
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ip": client_ip, "method": method, "path": path, "status": status,
    })
    # deque(maxlen=500) auto-discards oldest — no manual pop needed


def handle_gateway_info(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/info — Gateway status + uptime + instance count."""
    from ..core.registry import get_registry_path, cleanup_stale
    import platform

    instances = {}
    for eng in ("ida", "jeb"):
        entries = cleanup_stale(get_registry_path(eng))
        instances[eng] = len(entries)

    _send_json(handler, 200, {
        "status": "running",
        "host": gw_config.get("host", "0.0.0.0"),
        "port": gw_config.get("port", 8080),
        "uptime_sec": round(time.time() - _gateway_start_time, 1),
        "instances": instances,
        "total_instances": sum(instances.values()),
        "api_key_set": bool(gw_config.get("api_key")),
        "exec_enabled": gw_config.get("exec_enabled", False),
        "upload_limit_mb": gw_config.get("max_upload_size_mb", 500),
        "platform": platform.system(),
    })


def handle_gateway_config(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/config — Return server config (sensitive fields masked)."""
    from ..core.config import load_config
    try:
        config = load_config(gw_config.get("_config_path"))
    except Exception:
        config = {}

    # Mask sensitive fields
    safe = json.loads(json.dumps(config))
    if "gateway" in safe and safe["gateway"].get("api_key"):
        key = safe["gateway"]["api_key"]
        safe["gateway"]["api_key"] = key[:8] + "..." if len(key) > 8 else "***"
    if "security" in safe and safe["security"].get("auth_token_file"):
        safe["security"]["auth_token_file"] = "(masked)"

    _send_json(handler, 200, safe)


def handle_gateway_config_set(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/gateway/config — Update config key-value pair."""
    content_length = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(content_length) if content_length > 0 else b"{}"
    try:
        params = json.loads(body)
    except json.JSONDecodeError:
        _send_json(handler, 400, {"error": "Invalid JSON"})
        return

    key = params.get("key", "")
    value = params.get("value")
    if not key:
        _send_json(handler, 400, {"error": "key is required"})
        return

    # Security: block changing certain keys remotely
    blocked = {"security.auth_token_file"}
    if key in blocked:
        _send_json(handler, 403, {"error": f"Cannot modify '{key}' remotely"})
        return

    config_path = gw_config.get("_config_path")
    if not config_path:
        _send_json(handler, 500, {"error": "Config path not available"})
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        # Navigate nested keys: "gateway.port" → config["gateway"]["port"]
        parts = key.split(".")
        target = config
        for part in parts[:-1]:
            if part not in target:
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        _send_json(handler, 200, {"updated": key, "value": value})
    except Exception as e:
        _send_json(handler, 500, {"error": str(e)})


def handle_stop_all(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/gateway/stop-all — Stop all engine instances."""
    from ..core.registry import get_registry_path, cleanup_stale

    stopped = []
    failed = []
    for eng in ("ida", "jeb"):
        entries = cleanup_stale(get_registry_path(eng))
        for entry in entries:
            iid = entry.get("id", "")
            try:
                _rpc_to_instance(entry, "save_db", gw_config=gw_config)
            except Exception:
                pass
            try:
                _rpc_to_instance(entry, "stop", gw_config=gw_config)
            except Exception:
                pass  # JEB System.exit(0) → connection reset is expected

            # Verify process death with brief non-blocking poll
            pid = entry.get("pid")
            if pid:
                from ..core.instance import is_process_alive
                # Quick poll (no blocking sleep in HTTP thread)
                dead = not is_process_alive(pid)
                if not dead:
                    # Schedule background kill instead of blocking
                    import threading
                    def _deferred_kill(p, name):
                        import time as _t
                        _t.sleep(1)
                        if is_process_alive(p):
                            from ..core.process import force_kill
                            force_kill(p)
                            log.info("stop-all: deferred force-kill PID %d for %s", p, name)
                    threading.Thread(target=_deferred_kill, args=(pid, iid), daemon=True).start()
                stopped.append(iid)
            else:
                stopped.append(iid)

    _send_json(handler, 200, {
        "stopped": stopped,
        "failed": failed,
        "total": len(stopped) + len(failed),
    })


def handle_gateway_uploads(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/uploads — List files in upload directory."""
    from .upload import get_upload_dir
    upload_dir = get_upload_dir(gw_config)

    files = []
    total_size = 0
    for f in sorted(upload_dir.iterdir()):
        if f.is_file():
            size = f.stat().st_size
            total_size += size
            files.append({
                "name": f.name,
                "size": size,
                "modified": time.strftime("%Y-%m-%dT%H:%M:%S",
                                         time.localtime(f.stat().st_mtime)),
            })

    _send_json(handler, 200, {
        "dir": str(upload_dir),
        "files": files,
        "count": len(files),
        "total_size_mb": round(total_size / (1024 * 1024), 2),
    })


def handle_gateway_uploads_clean(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """DELETE /api/v1/gateway/uploads — Clean upload directory."""
    from .upload import get_upload_dir
    upload_dir = get_upload_dir(gw_config)

    removed = 0
    freed = 0
    for f in upload_dir.iterdir():
        if f.is_file():
            freed += f.stat().st_size
            f.unlink()
            removed += 1

    _send_json(handler, 200, {
        "removed": removed,
        "freed_mb": round(freed / (1024 * 1024), 2),
    })


def handle_gateway_audit(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/audit — Return recent audit log entries."""
    from pathlib import Path
    audit_path = gw_config.get("audit_path")
    if not audit_path:
        _send_json(handler, 404, {"error": "Audit path not configured"})
        return

    p = Path(os.path.expanduser(audit_path))
    if not p.exists():
        _send_json(handler, 200, {"entries": [], "count": 0})
        return

    # Parse query param ?tail=N
    query = handler.path.split("?", 1)[1] if "?" in handler.path else ""
    tail = 20
    for param in query.split("&"):
        if param.startswith("tail="):
            try:
                tail = int(param.split("=")[1])
            except ValueError:
                pass

    lines = p.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    recent = lines[-tail:] if len(lines) > tail else lines
    entries = []
    for line in recent:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"raw": line})

    _send_json(handler, 200, {"entries": entries, "count": len(entries), "total": len(lines)})


def handle_gateway_system(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/system — Server system info."""
    import platform
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }

    # revkit version
    try:
        import revkit
        info["revkit_version"] = getattr(revkit, "__version__", "unknown")
    except ImportError:
        info["revkit_version"] = "unknown"

    # CPU/RAM via psutil
    try:
        import psutil
        info["cpu_count"] = psutil.cpu_count()
        info["cpu_percent"] = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        info["ram_total_gb"] = round(mem.total / (1024**3), 1)
        info["ram_used_gb"] = round(mem.used / (1024**3), 1)
        info["ram_percent"] = mem.percent
    except ImportError:
        info["psutil"] = "not installed"

    # IDA/JEB versions
    try:
        from ..core.config import load_config
        config = load_config(gw_config.get("_config_path"))
        ida_dir = os.path.expanduser(config.get("ida", {}).get("install_dir", ""))
        jeb_dir = os.path.expanduser(config.get("jeb", {}).get("install_dir", ""))
        info["ida_dir"] = ida_dir if os.path.isdir(ida_dir) else f"{ida_dir} (not found)"
        info["jeb_dir"] = jeb_dir if os.path.isdir(jeb_dir) else f"{jeb_dir} (not found)"
    except Exception:
        pass

    _send_json(handler, 200, info)


def handle_gateway_disk(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/disk — Disk usage for key directories."""
    import shutil

    dirs = {}
    check_paths = {
        "upload_dir": gw_config.get("upload_dir", "~/.revkit/uploads"),
        "log_dir": "~/.revkit/logs",
        "home": "~",
    }

    for name, path in check_paths.items():
        p = os.path.expanduser(path)
        if os.path.exists(p):
            usage = shutil.disk_usage(p)
            dirs[name] = {
                "path": p,
                "total_gb": round(usage.total / (1024**3), 1),
                "used_gb": round(usage.used / (1024**3), 1),
                "free_gb": round(usage.free / (1024**3), 1),
                "percent": round(usage.used / usage.total * 100, 1),
            }

    _send_json(handler, 200, dirs)


def handle_gateway_cleanup(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/gateway/cleanup — Clean stale registry + zombie processes."""
    from ..core.registry import get_registry_path, cleanup_stale

    result = {}
    for eng in ("ida", "jeb"):
        reg_path = get_registry_path(eng)
        before = len(cleanup_stale(reg_path))
        entries = cleanup_stale(reg_path)
        result[eng] = {"active": len(entries), "cleaned": before - len(entries)}

    _send_json(handler, 200, result)


def handle_gateway_rotate_key(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/gateway/rotate-key — Generate new API key."""
    import secrets

    config_path = gw_config.get("_config_path")
    if not config_path:
        _send_json(handler, 500, {"error": "Config path not available"})
        return

    new_key = secrets.token_urlsafe(32)
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        config.setdefault("gateway", {})["api_key"] = new_key
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        # Hot-reload will pick up the new key
        _send_json(handler, 200, {"api_key": new_key, "note": "Update client config with new key"})
    except Exception as e:
        _send_json(handler, 500, {"error": str(e)})


def handle_gateway_allow_ip(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """POST /api/v1/gateway/allow-ip — Add/remove IP from allowed_ips."""
    content_length = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(content_length) if content_length > 0 else b"{}"
    try:
        params = json.loads(body)
    except json.JSONDecodeError:
        _send_json(handler, 400, {"error": "Invalid JSON"})
        return

    action = params.get("action", "add")  # add / remove / list
    ip_range = params.get("ip", "")

    config_path = gw_config.get("_config_path")
    if not config_path:
        _send_json(handler, 500, {"error": "Config path not available"})
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        allowed = config.get("gateway", {}).get("allowed_ips", [])

        if action == "list":
            _send_json(handler, 200, {"allowed_ips": allowed})
            return
        elif action == "add" and ip_range:
            if ip_range not in allowed:
                allowed.append(ip_range)
        elif action == "remove" and ip_range:
            if ip_range in allowed:
                allowed.remove(ip_range)
        else:
            _send_json(handler, 400, {"error": "action must be add/remove/list, ip required for add/remove"})
            return

        config.setdefault("gateway", {})["allowed_ips"] = allowed
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        _send_json(handler, 200, {"allowed_ips": allowed, "action": action, "ip": ip_range})
    except Exception as e:
        _send_json(handler, 500, {"error": str(e)})


def handle_gateway_connections(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/connections — Recent connection history."""
    query = handler.path.split("?", 1)[1] if "?" in handler.path else ""
    tail = 50
    for param in query.split("&"):
        if param.startswith("tail="):
            try:
                tail = int(param.split("=")[1])
            except ValueError:
                pass

    all_conns = list(_connection_log)
    recent = all_conns[-tail:] if tail < len(all_conns) else all_conns
    _send_json(handler, 200, {"connections": recent, "count": len(recent), "total": len(all_conns)})


def handle_gateway_download(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/gateway/download/{id} — Download a file from server."""
    file_id = match.group("id")
    from .upload import get_upload_dir

    # Search in uploads, idb, projects
    search_dirs = [get_upload_dir(gw_config)]
    try:
        from ..core.config import load_config
        config = load_config(gw_config.get("_config_path"))
        for key in ("idb_dir", "project_dir", "output_dir"):
            d = config.get("paths", {}).get(key)
            if d:
                from pathlib import Path
                search_dirs.append(Path(os.path.expanduser(d)))
    except Exception:
        pass

    # Find the file
    target = None
    for search_dir in search_dirs:
        for f in search_dir.rglob(f"*{file_id}*"):
            if f.is_file():
                target = f
                break
        if target:
            break

    if not target:
        _send_json(handler, 404, {"error": f"File not found: {file_id}"})
        return

    data = target.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/octet-stream")
    import urllib.parse as _urlparse
    safe_name = _urlparse.quote(target.name, safe='.-_')
    handler.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def handle_instance_logs(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/instances/{id}/logs — Instance log entries."""
    instance_id = match.group("id")
    instance = _find_instance(instance_id)

    query = handler.path.split("?", 1)[1] if "?" in handler.path else ""
    tail = 50
    for param in query.split("&"):
        if param.startswith("tail="):
            try:
                tail = int(param.split("=")[1])
            except ValueError:
                pass

    # Try log_path from registry, fallback to standard path
    log_path = None
    if instance:
        log_path = instance.get("log_path")
    if not log_path:
        from pathlib import Path
        for eng in ("ida", "jeb"):
            p = Path.home() / ".revkit" / "logs" / eng / "instances" / f"{instance_id}.jsonl"
            if p.exists():
                log_path = str(p)
                break

    if not log_path or not os.path.exists(log_path):
        _send_json(handler, 404, {"error": f"No logs found for instance {instance_id}"})
        return

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    recent = lines[-tail:]
    entries = []
    for line in recent:
        try:
            entries.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            entries.append({"raw": line.strip()})

    _send_json(handler, 200, {"instance_id": instance_id, "entries": entries, "count": len(entries)})


def handle_instance_progress(
    handler: BaseHTTPRequestHandler, gw_config: dict, match: re.Match
) -> None:
    """GET /api/v1/instances/{id}/progress — Analysis progress."""
    instance_id = match.group("id")
    instance = _find_instance(instance_id)
    if not instance:
        _send_json(handler, 404, {"error": f"Instance not found: {instance_id}"})
        return

    state = instance.get("state", "unknown")
    result = {"instance_id": instance_id, "state": state}

    # If ready, get live status from engine
    if state == "ready" and instance.get("port"):
        try:
            status = _rpc_to_instance(instance, "status", gw_config=gw_config)
            result.update(status)
        except Exception:
            pass

    _send_json(handler, 200, result)


# ──────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────


def _find_instance(instance_id: str) -> dict | None:
    """Look up instance across all engine registries. L10: uses cleanup_stale."""
    from ..core.registry import get_registry_path, cleanup_stale

    for engine_name in ("ida", "jeb"):
        reg_path = get_registry_path(engine_name)
        entries = cleanup_stale(reg_path)
        for entry in entries:
            if entry.get("id") == instance_id:
                return entry
    return None


def _resolve_auth_token(instance_id: str, instance: dict, gw_config: dict) -> str | None:
    """Resolve auth token: registry entry → auth_tokens file fallback."""
    token = instance.get("auth_token")
    if token:
        return token
    try:
        from ..core.config import load_config
        config = load_config(gw_config.get("_config_path"))
        token_file = os.path.expanduser(
            config.get("security", {}).get("auth_token_file", "~/.revkit/auth_tokens.json"))
        if os.path.exists(token_file):
            with open(token_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            # Format: id:port:token (one per line)
            for line in content.splitlines():
                parts = line.strip().split(":", 2)  # maxsplit=2: preserves colons in token
                if len(parts) == 3 and parts[0] == instance_id:
                    return parts[2]
    except Exception:
        pass
    return None


def _rpc_to_instance(instance: dict, method: str, params: dict | None = None,
                     gw_config: dict | None = None) -> dict:
    """Send RPC directly to an engine server instance."""
    port = instance.get("port")
    if not port:
        return {}
    iid = instance.get("id", "")
    url = f"http://127.0.0.1:{port}/"
    rpc_body = json.dumps({
        "jsonrpc": "2.0", "method": method,
        "params": params or {}, "id": 1,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    auth_token = _resolve_auth_token(iid, instance, gw_config or {})
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    req = urllib.request.Request(url, data=rpc_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _send_json(
    handler: BaseHTTPRequestHandler, status: int, data: Any
) -> None:
    """Send a JSON response."""
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler._response_status = status  # for _log_connection
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
