"""Gateway test fixtures."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from revkit.tools.gateway.auth import validate_api_key, check_ip_whitelist, extract_client_ip, _ip_in_list, authenticate, extract_bearer_token
from revkit.tools.gateway.audit import GatewayAuditLogger, _redact_params
from revkit.tools.gateway.config import load_gateway_config, validate_gateway_config, GATEWAY_DEFAULTS
from revkit.tools.gateway.daemon import GatewayDaemon, GatewayHandler
from revkit.tools.gateway.router import route_request, _send_json, handle_health
from revkit.tools.gateway.upload import (
    UploadError, get_upload_dir, parse_multipart, _extract_boundary,
    _validate_path, cleanup_upload, _check_disk_space,
)


TEST_API_KEY = "test-secret-key-12345"


@pytest.fixture
def gw_config(tmp_path):
    """Minimal gateway config for testing."""
    return {
        "host": "127.0.0.1",
        "port": 0,  # random port
        "max_upload_size_mb": 10,
        "upload_dir": str(tmp_path / "uploads"),
        "api_key": TEST_API_KEY,
        "allowed_ips": [],
        "trusted_proxies": [],
        "request_timeout": 5,
        "batch_timeout": 10,
        "log_rpc_params": False,
        "audit_path": str(tmp_path / "audit.jsonl"),
        "audit_max_size_mb": 1,
    }


@pytest.fixture
def gateway_server(gw_config):
    """Start a GatewayDaemon on a random port, yield (host, port, config), then shutdown."""
    server = GatewayDaemon(gw_config)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    gw_config["port"] = port
    yield host, port, gw_config
    server.shutdown()


@pytest.fixture
def mock_engine_server():
    """Mock JSON-RPC engine server. Yields (host, port, responses_dict)."""
    responses = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            method = body.get("method", "")
            if method in responses:
                result = responses[method]
            else:
                result = {"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"ok": True}}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            resp = json.dumps(result).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    yield host, port, responses
    server.shutdown()


@pytest.fixture
def sample_binary(tmp_path):
    """Create a small test binary file."""
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ" + b"\x00" * 1022)
    return p
