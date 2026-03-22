"""Tests for cli/remote.py — remote mode client."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from revkit.tools.cli.remote import (
    post_rpc_remote,
    upload_binary,
    remote_list,
)


@pytest.fixture
def mock_gateway():
    """Mock Gateway server for testing remote operations."""
    state = {"uploads": {}, "instances": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/v1/health":
                self._respond(200, {"status": "ok"})
            elif path == "/api/v1/instances":
                self._respond(200, {"instances": state["instances"]})
            else:
                self._respond(404, {"error": "Not found"})

        def do_POST(self):
            path = self.path.split("?")[0]
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            if path == "/api/v1/upload":
                file_id = "mock-file-id-123"
                state["uploads"][file_id] = body
                self._respond(200, {
                    "file_id": file_id,
                    "original_name": "test.bin",
                    "size": len(body),
                    "path": f"/uploads/{file_id}",
                })
            elif "/rpc" in path:
                try:
                    rpc = json.loads(body)
                except Exception:
                    rpc = {}
                self._respond(200, {
                    "jsonrpc": "2.0",
                    "id": rpc.get("id", 1),
                    "result": {"ok": True, "method": rpc.get("method")},
                })
            elif "/engines/" in path and "/start" in path:
                self._respond(501, {"error": "Not implemented"})
            else:
                self._respond(404, {"error": "Not found"})

        def _respond(self, status, data):
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    yield f"http://{host}:{port}", state
    server.shutdown()


def test_post_rpc_remote(mock_gateway):
    url, _ = mock_gateway
    result = post_rpc_remote(url, "inst1", "decompile", {"addr": "0x401000"})
    assert result["ok"] is True
    assert result["method"] == "decompile"


def test_post_rpc_remote_with_api_key(mock_gateway):
    url, _ = mock_gateway
    result = post_rpc_remote(url, "inst1", "test", api_key="secret-key")
    assert result["ok"] is True


def test_post_rpc_remote_nonexistent_instance(mock_gateway):
    url, _ = mock_gateway
    # Our mock just returns ok for any /rpc path, so this test verifies the request goes through
    result = post_rpc_remote(url, "nonexistent", "test")
    assert result["ok"] is True


def test_upload_binary(mock_gateway, tmp_path):
    url, state = mock_gateway
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    result = upload_binary(url, str(test_file))
    assert result["file_id"] == "mock-file-id-123"
    assert result["size"] > 0
    assert "mock-file-id-123" in state["uploads"]


def test_upload_binary_with_api_key(mock_gateway, tmp_path):
    url, _ = mock_gateway
    test_file = tmp_path / "test.apk"
    test_file.write_bytes(b"PK\x03\x04" + b"\x00" * 50)

    result = upload_binary(url, str(test_file), api_key="my-key")
    assert result["file_id"] == "mock-file-id-123"


def test_remote_list(mock_gateway):
    url, state = mock_gateway
    state["instances"] = [
        {"id": "inst1", "engine": "ida", "state": "ready"},
        {"id": "inst2", "engine": "jeb", "state": "starting"},
    ]
    instances = remote_list(url)
    assert len(instances) == 2
    assert instances[0]["id"] == "inst1"


def test_remote_list_empty(mock_gateway):
    url, _ = mock_gateway
    instances = remote_list(url)
    assert instances == []


def test_remote_unreachable():
    with pytest.raises(RuntimeError, match="unreachable"):
        post_rpc_remote("http://127.0.0.1:1", "inst1", "test", timeout=1)


def test_upload_unreachable(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"data")
    with pytest.raises(RuntimeError, match="unreachable"):
        upload_binary("http://127.0.0.1:1", str(test_file), timeout=1)
