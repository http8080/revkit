# -*- coding: utf-8 -*-
"""Server framework -- HTTP server, RPC dispatch, auth, registry, helpers.

This module runs under **Jython 2.7** (Python 2 syntax).
No f-strings, no type hints, no nonlocal, no Python 3 builtins.
"""

#?description=JEB Headless HTTP JSON-RPC Server

import json
import os
import time
import hashlib
import uuid

from .constants import SERVER_VERSION, MAX_REQUEST_BODY


# ─────────────────────────────────────────────
# RpcError
# ─────────────────────────────────────────────

class RpcError(Exception):
    """RPC error with code, message, and optional suggestion for the CLI."""
    def __init__(self, code, message, suggestion=None):
        self.code = code
        self.message = message
        self.suggestion = suggestion
        Exception.__init__(self, message)


# ─────────────────────────────────────────────
# File-based lock (replaces common.py acquire_lock / release_lock)
# ─────────────────────────────────────────────

def _acquire_lock(lock_path, timeout=1.0):
    """File-based mutex compatible with Jython 2.7."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except OSError:
            try:
                if time.time() - os.path.getmtime(lock_path) > 5:
                    os.remove(lock_path)
                    continue
            except OSError:
                pass
            time.sleep(0.05)
    return False


def _release_lock(lock_path):
    try:
        os.remove(lock_path)
    except OSError:
        pass


# ─────────────────────────────────────────────
# Registry read/write (standalone, no shared module)
# ─────────────────────────────────────────────

def _load_registry(registry_path):
    """Load registry file. Returns dict {instance_id: entry}.
    Handles both list [] (CLI format) and dict {} (server format)."""
    try:
        with open(registry_path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            # Convert CLI list format to dict format
            return dict((e["id"], e) for e in data if "id" in e)
        return {}
    except (IOError, ValueError):
        return {}


def _ensure_parent(path):
    """Create parent directory if it does not exist (Jython 2.7 safe)."""
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)


def _save_registry(registry_path, data):
    _ensure_parent(registry_path)
    content = json.dumps(data, indent=2, ensure_ascii=True)
    with open(registry_path, "w") as f:
        f.write(content)


# ─────────────────────────────────────────────
# Heartbeat / Watchdog / Cleanup (Java TimerTask)
# ─────────────────────────────────────────────

from java.util import Timer, TimerTask
from java.lang import Runtime, Thread as JThread


class HeartbeatTask(TimerTask):
    def __init__(self, server):
        TimerTask.__init__(self)
        self.server = server

    def run(self):
        self.server._update_registry(self.server.instance_id,
                                     {"last_heartbeat": time.time()})


class WatchdogTask(TimerTask):
    def __init__(self, server):
        TimerTask.__init__(self)
        self.server = server
        self.triggered = False

    def run(self):
        if not self.triggered:
            self.triggered = True
            self.server._update_registry(self.server.instance_id, {"state": "error"})
            self.server._log("open timeout -- forcing exit")
            from java.lang import System
            System.exit(1)


class CleanupHook(JThread):
    def __init__(self, server):
        JThread.__init__(self, "jeb-cleanup")
        self.server = server

    def run(self):
        s = self.server
        s._log_lifecycle("instance.stop")
        # save -> registry remove -> auth_token remove
        try:
            if s.engctx and s.prj:
                s.engctx.saveProject(s.prj.getKey(), s.project_path, None, None)
        except Exception:
            pass
        try:
            s._remove_from_registry(s.instance_id)
        except Exception:
            pass
        try:
            s._remove_auth_token(s.instance_id)
        except Exception:
            pass


# ─────────────────────────────────────────────
# RPC Handler (Java HttpServer / HttpHandler)
# ─────────────────────────────────────────────

from com.sun.net.httpserver import HttpHandler
from java.io import InputStreamReader, BufferedReader


class RpcHandler(HttpHandler):
    def __init__(self, jeb_server):
        self.server = jeb_server

    def handle(self, exchange):
        """All responses are HTTP 200 + JSON body (errors too)."""
        req_id = None
        method = None

        try:
            # 1. Host header validation (DNS rebinding defence)
            host = exchange.getRequestHeaders().getFirst("Host") or ""
            port = self.server.actual_port
            allowed = set(["127.0.0.1:%d" % port, "localhost:%d" % port])
            if host not in allowed:
                self._send_json(exchange, {
                    "error": {"code": "FORBIDDEN_HOST",
                              "message": "Invalid Host header"},
                    "id": None})
                return

            # 2. Auth (HMAC-safe compare via MessageDigest.isEqual)
            auth = exchange.getRequestHeaders().getFirst("Authorization") or ""
            expected = "Bearer " + self.server.auth_token
            from java.security import MessageDigest
            if not MessageDigest.isEqual(
                    bytearray(auth.encode("utf-8")),
                    bytearray(expected.encode("utf-8"))):
                self._send_json(exchange, {
                    "error": {"code": "AUTH_FAILED",
                              "message": "Invalid or missing auth token"},
                    "id": None})
                return

            result = None  # ensure defined for unicode error handler
            # 3. Parse request body (with size limit)
            reader = BufferedReader(
                InputStreamReader(exchange.getRequestBody(), "UTF-8"))
            body_parts = []
            total_len = 0
            while True:
                line = reader.readLine()
                if line is None:
                    break
                total_len += len(line)
                if total_len > MAX_REQUEST_BODY:
                    raise ValueError(
                        "Request body too large (%d bytes, max %d)"
                        % (total_len, MAX_REQUEST_BODY))
                body_parts.append(line)
            body_str = "\n".join(body_parts)
            try:
                request = json.loads(body_str)
            except ValueError:
                # Jython 2.7 JSON parser may fail on certain inputs;
                # try stripping trailing whitespace/newlines
                request = json.loads(body_str.strip())
            method = request.get("method")
            if not method:
                raise ValueError("Missing 'method' field")
            params = request.get("params")
            if params is None or not isinstance(params, dict):
                params = {}
            req_id = request.get("id", 1)

            # 4. Dispatch + timing log
            t0 = time.time()
            trace_id = params.pop("_trace_id", None)
            result = self.server.dispatch(method, params)
            elapsed = int((time.time() - t0) * 1000)
            rpc_data = {"method": method, "elapsed_ms": elapsed}
            if trace_id:
                rpc_data["trace_id"] = trace_id
            self.server._log("RPC %s -> OK (%dms)" % (method, elapsed), extra_data=rpc_data)
            self._send_json(exchange, {"result": result, "id": req_id})

        except RpcError as e:
            self.server._log("RPC %s -> %s: %s" % (
                method or "?", e.code, e.message), level="WARNING", extra_data={"method": method or "?", "error_code": e.code})
            self._send_json(exchange, {
                "error": {"code": e.code, "message": e.message,
                          "suggestion": e.suggestion},
                "id": req_id})
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            # Jython 2.7: unicode in response — retry with sanitized data
            self.server._log("RPC %s -> unicode retry" % (method or "?"))
            try:
                self._send_json(exchange, {
                    "result": self._sanitize_for_json(result),
                    "id": req_id})
            except Exception:
                self._send_json(exchange, {
                    "error": {"code": "ENCODING_ERROR",
                              "message": "Unicode encoding error in response"},
                    "id": req_id})
        except ValueError as e:
            self._send_json(exchange, {
                "error": {"code": "INVALID_PARAMS",
                          "message": "Malformed request: %s" % repr(e)},
                "id": req_id})
        except Exception as e:
            import traceback
            self.server._log("RPC %s -> INTERNAL: %s" % (
                method or "?", traceback.format_exc()), level="ERROR", extra_data={"method": method or "?"})
            try:
                err_msg = unicode(e)
            except (NameError, UnicodeEncodeError):
                err_msg = str(e)
            self._send_json(exchange, {
                "error": {"code": "INTERNAL", "message": err_msg},
                "id": req_id})
        except:
            # Bare except required in Jython to catch Java Throwable (NullPointerException etc.)
            # Re-raise SystemExit to allow clean shutdown
            import sys
            ei = sys.exc_info()
            if ei and ei[0] is SystemExit:
                raise
            import traceback
            self.server._log("RPC %s -> JAVA_ERROR: %s" % (
                method or "?", traceback.format_exc()), level="ERROR", extra_data={"method": method or "?"})
            self._send_json(exchange, {
                "error": {"code": "JAVA_ERROR", "message": "Java exception in handler"},
                "id": req_id})

    @staticmethod
    def _sanitize_for_json(obj):
        """Recursively convert Java/unicode strings to safe str for json.dumps."""
        if isinstance(obj, dict):
            return {RpcHandler._sanitize_for_json(k): RpcHandler._sanitize_for_json(v)
                    for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [RpcHandler._sanitize_for_json(v) for v in obj]
        try:
            if isinstance(obj, unicode):
                return obj.encode("unicode_escape").decode("ascii")
        except NameError:
            pass
        # Java String objects
        try:
            from java.lang import String as JS
            if isinstance(obj, JS):
                return obj.encode("unicode_escape").decode("ascii") if hasattr(obj, "encode") else repr(obj)
        except ImportError:
            pass
        return obj

    def _send_json(self, exchange, obj):
        """HTTP 200 + JSON response (always 200, matching IDA pattern)."""
        from java.lang import String as JString
        try:
            response_str = json.dumps(obj, ensure_ascii=True)
        except (UnicodeEncodeError, UnicodeDecodeError):
            response_str = json.dumps(self._sanitize_for_json(obj), ensure_ascii=True)
        resp_bytes = JString(response_str).getBytes("UTF-8")
        exchange.getResponseHeaders().add(
            "Content-Type", "application/json; charset=utf-8")
        exchange.sendResponseHeaders(200, len(resp_bytes))
        out = exchange.getResponseBody()
        out.write(resp_bytes)
        out.close()


# ─────────────────────────────────────────────
# JebServer (IScript implementation)
# ─────────────────────────────────────────────

from com.pnfsoftware.jeb.client.api import IScript


class JebServer(IScript):
    """JEB Headless HTTP JSON-RPC Server.

    Implements the IScript interface so JEB can invoke it via headless mode.
    All RPC handler methods are instance methods dispatched via ``_METHODS``.
    """

    # ── Methods that modify the project (trigger auto_save) ──
    _MUTATING_METHODS = frozenset([
        "rename", "rename_class", "rename_method", "rename_field", "rename_batch",
        "set_comment", "import_annotations", "auto_rename", "undo",
    ])

    # ── Method registry (string -> handler name, resolved via getattr) ──
    _METHODS = {
        # System API
        "ping":                         "_handle_ping",
        "status":                       "_handle_status",
        "stop":                         "_handle_stop",
        "methods":                      "_handle_methods",
        "save":                         "_handle_save",
        # DEX/APK analysis API
        "get_classes":                  "_handle_get_classes",
        "get_methods_of_class":         "_handle_get_methods_of_class",
        "get_fields_of_class":          "_handle_get_fields_of_class",
        "get_method_info":              "_handle_get_method_info",
        "get_imports":                  "_handle_get_imports",
        "get_exports":                  "_handle_get_exports",
        "native_methods":               "_handle_native_methods",
        "get_class_source":             "_handle_get_class_source",
        "get_method_by_name":           "_handle_get_method_by_name",
        "get_class_source_with_xrefs":  "_handle_get_class_source_with_xrefs",
        "decompile_batch":              "_handle_decompile_batch",
        "decompile_all":                "_handle_decompile_all",
        "get_smali":                    "_handle_get_smali",
        "get_manifest":                 "_handle_get_manifest",
        "get_strings":                  "_handle_get_strings",
        "strings_xrefs":               "_handle_strings_xrefs",
        "get_xrefs":                    "_handle_get_xrefs",
        "cross_refs":                   "_handle_cross_refs",
        "callgraph":                    "_handle_callgraph",
        "search_classes":               "_handle_search_classes",
        "search_methods":               "_handle_search_methods",
        "search_code":                  "_handle_search_code",
        "get_resources_list":           "_handle_get_resources_list",
        "get_resource":                 "_handle_get_resource",
        "get_main_activity":            "_handle_get_main_activity",
        "get_app_classes":              "_handle_get_app_classes",
        # Modification / annotation API
        "rename":                       "_handle_rename",
        "rename_class":                 "_handle_rename_class",
        "rename_method":                "_handle_rename_method",
        "rename_field":                 "_handle_rename_field",
        "rename_batch":                 "_handle_rename_batch",
        "set_comment":                  "_handle_set_comment",
        "get_comments":                 "_handle_get_comments",
        "undo":                         "_handle_undo",
        "export_annotations":           "_handle_export_annotations",
        "import_annotations":           "_handle_import_annotations",
        # Advanced API
        "auto_rename":                  "_handle_auto_rename",
        "summary":                      "_handle_summary",
        "info":                         "_handle_info",
        "exec":                         "_handle_exec",
        # Snapshot API
        "snapshot_save":                "_handle_snapshot_save",
        "snapshot_list":                "_handle_snapshot_list",
        "snapshot_restore":             "_handle_snapshot_restore",
        # CLI compatibility aliases
        "decompile":                    "_handle_get_class_source",
        "decompile_with_xrefs":         "_handle_get_class_source_with_xrefs",
        "save_project":                 "_handle_save",
        "get_xrefs_to":                 "_handle_get_xrefs",
        "get_xrefs_from":              "_handle_get_xrefs",
        "get_resources":                "_handle_get_resources_list",
        "get_app_class":                "_handle_get_app_classes",
        # #49, #50: Security analysis
        "entry_points":                 "_handle_entry_points",
        "security_scan":                "_handle_security_scan",
        # Remote test additions
        "rename_preview":               "_handle_rename_preview",
        "report":                       "_handle_report",
        "decompile_diff":               "_handle_decompile_diff",
    }

    # ─────────────────────────────────────────
    # IScript entry point
    # ─────────────────────────────────────────

    def run(self, ctx):
        """Main entry -- called by JEB headless runner.

        Args layout (ctx.getArguments()):
            [0] binary_path
            [1] instance_id
            [2] project_path (.jdb2)
            [3] log_path
            [4] config_path
            [5] "--fresh" (optional)
        """
        args = ctx.getArguments()

        # 0. Config parsing + path init
        self.binary_path = args[0]
        self.instance_id = args[1]
        self.project_path = args[2]
        # Ensure .jdb2 extension for project save path
        if not self.project_path.endswith(".jdb2"):
            self.project_path = self.project_path + ".jdb2"
        self.log_path = args[3]
        self.start_time = time.time()

        with open(args[4], "r") as f:
            cfg = json.load(f)

        # Merge engine-specific security into global security
        engine_security = cfg.get("jeb", {}).get("security", {})
        if engine_security:
            cfg.setdefault("security", {}).update(engine_security)
        self.config = cfg
        self._log_lifecycle("instance.start", extra={"binary": self.binary_path, "pid": os.getpid()})
        # Registry path: from config jeb.registry, fallback ~/.revkit/jeb/registry.json
        _jeb_reg = cfg.get("jeb", {}).get("registry", "")
        if _jeb_reg:
            self.registry_path = self._expand_path(_jeb_reg)
        else:
            _home = os.path.expanduser("~")
            self.registry_path = os.path.join(_home, ".revkit", "jeb", "registry.json")
        self.auth_token_path = self._expand_path(
            cfg.get("security", {}).get("auth_token_file", "~/.revkit/auth_tokens.json")
        )
        self.default_count = cfg.get("output", {}).get("default_count", 100)
        self.max_count = cfg.get("output", {}).get("max_count", 500)
        self.auto_save = cfg.get("analysis", {}).get("auto_save", True)

        # 1. --fresh handling: delete existing .jdb2 project file
        fresh = len(args) > 5 and args[5] == "--fresh"
        if fresh and os.path.exists(self.project_path):
            os.remove(self.project_path)

        # 2. Registry update (state: analyzing)
        pid_create_time = None
        try:
            from java.lang.management import ManagementFactory
            pid_create_time = ManagementFactory.getRuntimeMXBean().getStartTime() / 1000.0
        except Exception:
            pass

        self._update_registry(self.instance_id, {
            "state": "analyzing",
            "pid": os.getpid(),
            "pid_create_time": pid_create_time,
            "binary": os.path.basename(args[0]),
            "path": args[0],
            "project_path": self.project_path,
            "log_path": self.log_path,
            "started": time.time(),
            "last_heartbeat": time.time(),
        })

        # 3. Watchdog timer (cancel after successful open)
        open_timeout = cfg.get("analysis", {}).get("open_timeout", 600)
        watchdog_timer = Timer(True)  # daemon
        watchdog_task = WatchdogTask(self)
        watchdog_timer.schedule(watchdog_task, long(open_timeout * 1000))

        # 4. Open file + analysis (reuse .jdb2 if available)
        loaded_from_jdb2 = False
        if not fresh and os.path.exists(self.project_path):
            try:
                self._log("Loading existing project: %s" % self.project_path)
                engctx = ctx.getEnginesContext()
                prj = engctx.loadProject(self.project_path)
                if prj:
                    loaded_from_jdb2 = True
                    self._log("Project loaded from .jdb2 (%d bytes)" % os.path.getsize(self.project_path))
                else:
                    self._log("loadProject returned None, falling back to fresh open")
            except Exception as e:
                self._log("loadProject failed: %s, falling back to fresh open" % str(e))
                prj = None

        if not loaded_from_jdb2:
            ctx.open(args[0])
            prj = ctx.getMainProject()

        if not prj:
            self._update_registry(self.instance_id, {"state": "error"})
            self._log_lifecycle("instance.error", extra={"reason": "Failed to get project"})
            raise Exception("Failed to get project after open: %s" % args[0])
        self._log_lifecycle("instance.db_open", extra={
            "project_path": self.project_path,
            "loaded_from_jdb2": loaded_from_jdb2,
        })

        self.loaded_from_jdb2 = loaded_from_jdb2

        # Cancel watchdog (open succeeded)
        watchdog_task.triggered = True
        watchdog_timer.cancel()

        # 5. Cache JEB units (IDexUnit, IApkUnit, etc.)
        self._cache_units(ctx, prj)

        class_count = sum(dex.getClasses().size() for dex in self.dex_units)
        method_count = sum(dex.getMethods().size() for dex in self.dex_units)
        self._log_lifecycle("instance.metadata", extra={
            "binary": os.path.basename(self.binary_path),
            "class_count": class_count,
            "method_count": method_count,
            "dex_count": len(self.dex_units),
            "has_apk": self.apk_unit is not None,
        })

        # 6. Generate auth token (server-side, not via command line)
        self.auth_token = str(uuid.uuid4()).replace("-", "")

        # 7. Start Java HttpServer
        from com.sun.net.httpserver import HttpServer
        from java.net import InetSocketAddress

        http_server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        http_server.createContext("/", RpcHandler(self))
        http_server.start()
        self.actual_port = http_server.getAddress().getPort()

        # 8. Save auth token file (CLI reads from here)
        self._save_auth_token(self.instance_id, self.actual_port, self.auth_token)

        # 9. Start heartbeat timer
        self._start_heartbeat(cfg)

        # 10. Registry update (state: ready, with port)
        self._update_registry(self.instance_id, {
            "state": "ready",
            "port": self.actual_port,
            "last_heartbeat": time.time(),
        })

        # 11. Ready banner (stdout, same as IDA)
        print("\n" + "=" * 50)
        print("  jeb_server ready")
        print("  URL:   http://127.0.0.1:%d" % self.actual_port)
        print("  Token: %s" % self.auth_token)
        print("  ID:    %s" % self.instance_id)
        print("=" * 50 + "\n")
        self._log_lifecycle("instance.ready", extra={"port": self.actual_port})

        # 12. Register shutdown cleanup hook
        self._register_cleanup_hook()

        # 13. Block main thread (keep process alive)
        from java.util.concurrent import CountDownLatch
        self.shutdown_latch = CountDownLatch(1)
        self.shutdown_latch.await()

        # 14. Cleanup after latch release
        http_server.stop(0)
        self._log("Shutdown complete, exiting JVM")
        System.exit(0)

    # ─────────────────────────────────────────
    # Dispatch
    # ─────────────────────────────────────────

    # Param alias mapping: CLI key -> handler keys
    # Allows callers to use either documented names or internal handler names
    _PARAM_ALIASES = {
        "sig": ("class_sig", "item_sig", "method_sig", "field_sig"),
        "class": ("class_sig",),
        "target": ("item_sig", "class_sig"),
        "method": ("method_sig",),
        "field": ("field_sig",),
        "address": ("addr",),
        "sigs": ("class_sigs",),
        "classes": ("class_sigs",),
        "renames": ("entries",),
    }

    def dispatch(self, method, params):
        """RPC method dispatch."""
        for src, targets in self._PARAM_ALIASES.items():
            if src in params:
                for t in targets:
                    if t not in params:
                        params[t] = params[src]
        handler_name = self._METHODS.get(method)
        if not handler_name:
            raise RpcError("UNKNOWN_METHOD", "Unknown method: %s" % method,
                           "Call 'methods' to list available APIs")
        handler = getattr(self, handler_name, None)
        if not handler:
            raise RpcError("NOT_IMPLEMENTED", "Not implemented: %s" % method,
                           "This method is registered but has no handler yet")
        result = handler(params)
        # Auto-save after mutation methods
        if self.auto_save and method in self._MUTATING_METHODS:
            try:
                self.engctx.saveProject(self.prj.getKey(), self.project_path, None, None)
            except Exception:
                pass
        return result

    # ─────────────────────────────────────────
    # System handlers
    # ─────────────────────────────────────────

    def _handle_ping(self, params):
        """Health check"""
        return {"ok": True, "state": "ready"}

    def _handle_status(self, params):
        """Project status"""
        class_count = sum(dex.getClasses().size() for dex in self.dex_units)
        method_count = sum(dex.getMethods().size() for dex in self.dex_units)
        binary_md5 = self._file_md5(self.binary_path)
        jeb_cfg = self.config.get("jeb", {})
        spawn_method = jeb_cfg.get("spawn_method", "wrapper")
        result = {
            "state": "ready",
            "binary": os.path.basename(self.binary_path),
            "project_path": self.project_path,
            "binary_md5": binary_md5,
            "class_count": class_count,
            "method_count": method_count,
            "dex_count": len(self.dex_units),
            "jeb_version": str(self.ctx.getSoftwareVersion()),
            "server_version": SERVER_VERSION,
            "uptime": round(time.time() - self.start_time, 1),
            "spawn_method": spawn_method,
            "loaded_from_jdb2": getattr(self, "loaded_from_jdb2", False),
        }
        if spawn_method == "wrapper":
            java_home = jeb_cfg.get("java_home", "")
            jvm_opts = jeb_cfg.get("jvm_opts", [])
            if java_home:
                result["java_home"] = java_home
            if jvm_opts:
                result["jvm_opts"] = jvm_opts
        return result

    def _handle_stop(self, params):
        """Shut down server (save project, clean registry, release latch)"""
        try:
            self.engctx.saveProject(self.prj.getKey(), self.project_path, None, None)
        except Exception:
            pass
        # Clean up registry and auth token BEFORE shutdown
        # (CLI checks registry/process to confirm stop)
        try:
            self._remove_from_registry(self.instance_id)
        except Exception:
            pass
        try:
            self._remove_auth_token(self.instance_id)
        except Exception:
            pass
        # Delay latch release so HTTP response can be sent first
        server_ref = self

        class StopTask(TimerTask):
            def run(self):
                server_ref.shutdown_latch.countDown()

        Timer(True).schedule(StopTask(), long(100))
        return {"ok": True}

    def _handle_methods(self, params):
        """List available RPC methods"""
        methods = []
        for name in sorted(self._METHODS):
            handler_name = self._METHODS[name]
            handler = getattr(self, handler_name, None)
            doc = ""
            if handler and handler.__doc__:
                doc = handler.__doc__.strip().split("\n")[0]
            methods.append({"name": name, "description": doc})
        return {"methods": methods}

    def _handle_save(self, params):
        """Save project to disk"""
        key = self.prj.getKey()
        ok = self.engctx.saveProject(key, self.project_path, None, None)
        return {"ok": ok, "project_path": self.project_path}

    # ─────────────────────────────────────────
    # Unit cache helpers
    # ─────────────────────────────────────────

    def _cache_units(self, ctx, prj):
        """Cache IDexUnit, IApkUnit, IEnginesContext from the project."""
        from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
        self.ctx = ctx
        self.prj = prj
        self.engctx = ctx.getEnginesContext()
        self.dex_units = list(prj.findUnits(IDexUnit))
        self.apk_unit = prj.findUnit(IApkUnit)

    def _find_dex_for(self, getter_name, sig):
        """Return the IDexUnit containing sig via getter_name, or None."""
        for dex in self.dex_units:
            if getattr(dex, getter_name)(sig):
                return dex
        return None

    def _find_dex_for_class(self, class_sig):
        """Return the IDexUnit containing class_sig, or None."""
        return self._find_dex_for("getClass", class_sig)

    def _find_dex_for_method(self, method_sig):
        """Return the IDexUnit containing method_sig, or None."""
        return self._find_dex_for("getMethod", method_sig)

    def _find_dex_for_any(self, item_sig):
        """Return IDexUnit for class/method/field sig, or None."""
        for getter in ("getMethod", "getClass", "getField"):
            dex = self._find_dex_for(getter, item_sig)
            if dex:
                return dex
        return None

    # ─────────────────────────────────────────
    # Pagination / output helpers
    # ─────────────────────────────────────────

    def _paginate(self, items, params):
        """Offset/count pagination with optional filter and file save."""
        filt = params.get("filter")
        if filt:
            filt_lower = filt.lower()
            items = [it for it in items
                     if self._match_filter(it, filt_lower)]
        total = len(items)
        offset = max(0, int(params.get("offset", 0)))
        count = max(0, min(int(params.get("count", self.default_count)),
                           self.max_count))
        page = items[offset:offset + count]
        saved_to = self._save_output(params.get("output"), page, fmt="json")
        return {
            "total": total,
            "offset": offset,
            "count": len(page),
            "data": page,
            "saved_to": saved_to,
        }

    @staticmethod
    def _match_filter(item, filt_lower):
        """Check if any string value in item dict contains the filter text."""
        if isinstance(item, dict):
            for v in item.values():
                try:
                    s = unicode(v) if v is not None else ""
                except NameError:
                    s = str(v) if v is not None else ""
                if filt_lower in s.lower():
                    return True
            return False
        try:
            return filt_lower in str(item).lower()
        except Exception:
            return False

    def _save_output(self, output_path, content, fmt="text"):
        """Save content to file. fmt: 'text' or 'json'."""
        output_path = self._validate_output_path(output_path)
        if not output_path:
            return None
        _ensure_parent(output_path)
        if isinstance(content, (bytes, bytearray)):
            with open(output_path, "wb") as f:
                f.write(content)
        elif fmt == "json":
            data_str = json.dumps(content, ensure_ascii=True, indent=2)
            with open(output_path, "w") as f:
                f.write(data_str)
        else:
            with open(output_path, "w") as f:
                try:
                    f.write(unicode(content))
                except NameError:
                    f.write(str(content))
        return output_path

    def _validate_output_path(self, output_path):
        """Validate output path is under allowed directory.

        If output_dir is configured and path is outside it, skip server-side
        save (return None). The CLI will save locally instead.
        """
        if not output_path:
            return None
        abspath = os.path.abspath(output_path)
        allowed = self.config.get("paths", {}).get("output_dir")
        if allowed:
            allowed_abs = os.path.abspath(os.path.expanduser(allowed))
            if not abspath.startswith(allowed_abs + os.sep) and abspath != allowed_abs:
                import sys
                print("[WARN] Output path %s is outside output_dir %s, skipping server-side save"
                      % (output_path, allowed))
                sys.stdout.flush()
                return None
        return abspath

    # ─────────────────────────────────────────
    # Registry / auth token methods
    # ─────────────────────────────────────────

    def _with_lock(self, fn):
        """Execute fn() while holding the registry lock."""
        lock_path = self.registry_path + ".lock"
        if not _acquire_lock(lock_path):
            self._log("WARNING: Could not acquire registry lock")
            return
        try:
            fn()
        finally:
            _release_lock(lock_path)

    def _update_registry(self, instance_id, updates):
        """Update instance info in the registry file (with lock)."""
        def _do():
            reg = _load_registry(self.registry_path)
            if instance_id not in reg:
                reg[instance_id] = {}
            reg[instance_id].update(updates)
            _save_registry(self.registry_path, reg)
        self._with_lock(_do)

    def _remove_from_registry(self, instance_id):
        """Remove instance from the registry file."""
        def _do():
            reg = _load_registry(self.registry_path)
            if instance_id in reg:
                del reg[instance_id]
            _save_registry(self.registry_path, reg)
        self._with_lock(_do)

    def _update_auth_tokens(self, instance_id, new_line=None):
        """Filter out old entries for instance_id; optionally append new_line."""
        def _do():
            lines = []
            if os.path.exists(self.auth_token_path):
                with open(self.auth_token_path, "r") as f:
                    lines = [l for l in f.readlines()
                             if not l.startswith("%s:" % instance_id)]
            elif not new_line:
                return
            if new_line:
                lines.append(new_line)
            _ensure_parent(self.auth_token_path)
            with open(self.auth_token_path, "w") as f:
                f.writelines(lines)
        self._with_lock(_do)

    def _save_auth_token(self, instance_id, port, token):
        """Append auth token entry for this instance."""
        self._update_auth_tokens(instance_id,
                                  "%s:%d:%s\n" % (instance_id, port, token))

    def _remove_auth_token(self, instance_id):
        """Remove auth token entry for this instance."""
        self._update_auth_tokens(instance_id)

    # ─────────────────────────────────────────
    # Heartbeat / cleanup
    # ─────────────────────────────────────────

    def _start_heartbeat(self, cfg):
        """Start the heartbeat timer (daemon thread)."""
        hb_interval = cfg.get("analysis", {}).get("heartbeat_interval", 60)
        self._heartbeat_timer = Timer(True)  # daemon
        self._heartbeat_timer.scheduleAtFixedRate(
            HeartbeatTask(self),
            long(hb_interval * 1000),
            long(hb_interval * 1000))

    def _register_cleanup_hook(self):
        """Register JVM shutdown hook for graceful cleanup."""
        Runtime.getRuntime().addShutdownHook(CleanupHook(self))

    # ─────────────────────────────────────────
    # Path / File utilities
    # ─────────────────────────────────────────

    @staticmethod
    def _expand_path(s):
        """Expand environment variable placeholders in a config path."""
        if s.startswith("~"):
            s = os.path.expanduser(s)
        for placeholder, envvar in [
            ("%USERPROFILE%", "USERPROFILE"),
            ("%TEMP%", "TEMP"),
            ("$HOME", "HOME"),
        ]:
            if placeholder in s:
                s = s.replace(placeholder, os.environ.get(envvar, ""))
        return os.path.normpath(s)

    @staticmethod
    def _file_md5(path):
        """Compute MD5 hash of a file, or None if not found."""
        if not os.path.exists(path):
            return None
        h = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    # ─────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────

    def _log(self, msg, level="INFO", extra_data=None):
        """Append JSONL log line to the log file (with rotation)."""
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "iid": self.instance_id,
            "msg": msg,
        }
        if extra_data:
            entry["data"] = extra_data
        try:
            self._maybe_rotate_log()
            line = json.dumps(entry, ensure_ascii=True) + "\n"
            with open(self.log_path, "a") as f:
                f.write(line)
        except (IOError, OSError, TypeError):
            pass

    def _log_lifecycle(self, event, extra=None):
        """Log a lifecycle event with structured data."""
        data = {"iid": self.instance_id, "event": event}
        if extra:
            data.update(extra)
        self._log("lifecycle: %s" % event, extra_data=data)

    def _maybe_rotate_log(self):
        """Rotate log file if it exceeds max_size_mb."""
        try:
            if not os.path.exists(self.log_path):
                return
            max_bytes = self.config.get("log", {}).get("max_size_mb", 50) * 1024 * 1024
            if os.path.getsize(self.log_path) < max_bytes:
                return
            backup_count = self.config.get("log", {}).get("backup_count", 3)
            # Rotate: remove oldest, shift others up, rename current to .1
            oldest = "%s.%d" % (self.log_path, backup_count)
            if os.path.exists(oldest):
                os.remove(oldest)
            for i in range(backup_count - 1, 0, -1):
                src = "%s.%d" % (self.log_path, i)
                if os.path.exists(src):
                    os.rename(src, "%s.%d" % (self.log_path, i + 1))
            os.rename(self.log_path, "%s.1" % self.log_path)
        except (IOError, OSError):
            pass


# ─────────────────────────────────────────────
# Public entry point (called from __init__.py)
# ─────────────────────────────────────────────

def _bind_handlers():
    """Bind handler functions from handlers.py as JebServer methods."""
    from . import handlers
    bound = set()
    for name in dir(handlers):
        if name.startswith("_handle_"):
            func = getattr(handlers, name)
            if callable(func):
                setattr(JebServer, name, func)
                bound.add(name)
    JebServer.RpcError = RpcError
    # Verify all registered methods have handlers
    for method, handler_name in JebServer._METHODS.items():
        if handler_name.startswith("_handle_") and not hasattr(JebServer, handler_name):
            raise ImportError("Missing handler %s for RPC method '%s'" % (handler_name, method))

_bind_handlers()


def run_server(ctx):
    """Instantiate JebServer and invoke its run() method.

    This is the function that ``main(ctx)`` in ``__init__.py`` calls.
    """
    server = JebServer()
    server.run(ctx)
