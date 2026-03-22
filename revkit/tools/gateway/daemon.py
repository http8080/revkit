"""revkit gateway — HTTP gateway daemon.

ThreadingHTTPServer-based gateway with graceful shutdown.
Binds to configurable host:port, routes API requests, and
handles authentication before dispatching.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .auth import authenticate, extract_bearer_token, extract_client_ip
from .audit import GatewayAuditLogger
from .config import load_gateway_config, validate_gateway_config
from .router import route_request
from ..core.logging_setup import get_gateway_logger

log = get_gateway_logger()

PUBLIC_PATHS = frozenset({"/api/v1/health"})


class GatewayHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the gateway."""

    server: GatewayDaemon

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def _handle(self) -> None:
        t0 = time.time()
        gw_config = self.server.gw_config
        path = self.path.split("?")[0]
        client_ip = extract_client_ip(self, gw_config.get("trusted_proxies", []))

        if path not in PUBLIC_PATHS:
            if not authenticate(self, gw_config):
                self._send_error(403, "Forbidden")
                self._audit(t0, client_ip, 403)
                return

        try:
            route_request(self, gw_config)
        except Exception as e:
            log.exception("Unhandled error in gateway handler")
            self._send_error(500, "Internal server error")

        # Use actual response status (set by _send_json/_send_error), default 200
        actual_status = getattr(self, '_response_status', 200)
        self._audit(t0, client_ip, actual_status)

    def _send_error(self, status: int, message: str) -> None:
        self._response_status = status  # Track for audit logging
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _audit(self, t0: float, client_ip: str, status: int) -> None:
        if self.server.audit_logger:
            elapsed_ms = (time.time() - t0) * 1000
            api_key_id = None
            token = extract_bearer_token(self)
            if token and len(token) >= 8:
                api_key_id = token[:8] + "..."
            self.server.audit_logger.log_request(
                method=self.command,
                path=self.path,
                status=status,
                source_ip=client_ip,
                elapsed_ms=elapsed_ms,
                api_key_id=api_key_id,
            )

    def log_message(self, format: str, *args) -> None:
        log.info("%s - %s", self.client_address[0], format % args)


class GatewayDaemon(ThreadingHTTPServer):
    """ThreadingHTTPServer subclass carrying gateway config and audit logger."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        gw_config: dict,
        audit_logger: GatewayAuditLogger | None = None,
    ):
        self.gw_config = gw_config
        self.audit_logger = audit_logger
        host = gw_config.get("host", "0.0.0.0")
        port = gw_config.get("port", 8080)
        super().__init__((host, port), GatewayHandler)

    def health(self) -> dict:
        """Return gateway health status."""
        return {
            "status": "running",
            "host": self.server_address[0],
            "port": self.server_address[1],
        }


class ConfigWatcher:
    """Watch config file for changes and trigger reload."""

    def __init__(self, config_path: str, interval: float = 2.0):
        self.config_path = config_path
        self.interval = interval
        self._last_mtime = self._get_mtime()
        self._stop = threading.Event()

    def _get_mtime(self) -> float:
        try:
            import os
            return os.path.getmtime(self.config_path)
        except OSError:
            return 0.0

    def watch(self, on_change):
        """Poll config file mtime. Calls on_change() when modified."""
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            mtime = self._get_mtime()
            if mtime > self._last_mtime:
                self._last_mtime = mtime
                log.info("Config file changed, reloading...")
                try:
                    on_change()
                except Exception:
                    log.exception("Failed to reload config")

    def stop(self):
        self._stop.set()


def run_gateway(config: dict, config_path: str | None = None) -> None:
    """Start the gateway daemon with graceful shutdown and config hot-reload.

    Args:
        config: Full config dict (gateway section will be extracted).
        config_path: Path to config.json for hot-reload watching.
    """
    gw_config = load_gateway_config(config)
    if config_path:
        gw_config["_config_path"] = config_path  # for management endpoints
    errors = validate_gateway_config(gw_config)
    if errors:
        for e in errors:
            log.error("Config error: %s", e)
        sys.exit(1)

    audit_logger = GatewayAuditLogger(
        audit_path=gw_config.get("audit_path"),
        max_size_mb=gw_config.get("audit_max_size_mb", 100),
        log_rpc_params=gw_config.get("log_rpc_params", False),
    )

    try:
        server = GatewayDaemon(gw_config, audit_logger)
    except OSError as e:
        port = gw_config.get("port", 8080)
        host = gw_config.get("host", "0.0.0.0")
        log.error("Cannot bind to %s:%d — %s", host, port, e)
        sys.exit(1)

    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    host, port = server.server_address
    log.info("Gateway listening on %s:%d", host, port)

    # Config hot-reload: watch for file changes
    reload_event = threading.Event()
    watcher = None

    if config_path:
        from ..core.config import load_config as _load_config

        def _on_config_change():
            try:
                new_config = _load_config(config_path)
                new_gw = load_gateway_config(new_config)
                new_host = new_gw.get("host", "0.0.0.0")
                new_port = new_gw.get("port", 8080)
                old_host, old_port = server.server_address

                if (new_host, new_port) != (old_host, old_port):
                    log.info("Port/host changed (%s:%d -> %s:%d), restarting...",
                             old_host, old_port, new_host, new_port)
                    reload_event.set()
                else:
                    # Hot-reload without restart: api_key, allowed_ips, timeouts, etc.
                    new_gw["_config_path"] = config_path
                    server.gw_config = new_gw
                    log.info("Config reloaded (api_key, allowed_ips, timeouts updated)")
            except Exception:
                log.exception("Config reload failed, keeping current config")

        watcher = ConfigWatcher(config_path)
        watcher_thread = threading.Thread(target=watcher.watch, args=(_on_config_change,),
                                          daemon=True)
        watcher_thread.start()
        log.info("Config watcher started (checking every %.1fs)", watcher.interval)

    shutdown_event = threading.Event()

    def _handle_signal(signum, frame):
        log.info("Received signal %s, shutting down...", signum)
        shutdown_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    if sys.platform == "win32":
        try:
            signal.signal(signal.SIGBREAK, _handle_signal)
        except (AttributeError, OSError):
            pass

    # Wait for shutdown or restart
    while not shutdown_event.is_set():
        if reload_event.is_set():
            # Port/host changed — full restart
            reload_event.clear()
            log.info("Restarting gateway...")
            server.shutdown()
            if watcher:
                watcher.stop()

            config = _load_config(config_path)
            gw_config = load_gateway_config(config)
            gw_config["_config_path"] = config_path
            server = GatewayDaemon(gw_config, audit_logger)
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()

            host, port = server.server_address
            log.info("Gateway restarted on %s:%d", host, port)

            watcher = ConfigWatcher(config_path)
            watcher_thread = threading.Thread(target=watcher.watch, args=(_on_config_change,),
                                              daemon=True)
            watcher_thread.start()
        shutdown_event.wait(1.0)

    log.info("Shutting down gateway...")
    if watcher:
        watcher.stop()
    server.shutdown()
    log.info("Gateway stopped.")


if __name__ == "__main__":
    import argparse
    from ..core.config import load_config

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="revkit gateway daemon")
    parser.add_argument("--config", required=True, help="Path to config.json")
    args = parser.parse_args()

    cfg = load_config(args.config)
    run_gateway(cfg, config_path=args.config)
