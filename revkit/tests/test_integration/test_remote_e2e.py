"""Remote end-to-end tests (mock Gateway)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from revkit.tools.cli.remote import post_rpc_remote, upload_binary, remote_list


@pytest.fixture
def mock_gw():
    """Minimal mock Gateway."""
    state = {"instances": [], "uploads": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/v1/instances":
                self._respond(200, {"instances": state["instances"]})
            elif path == "/api/v1/health":
                self._respond(200, {"status": "ok"})
            else:
                self._respond(404, {"error": "Not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            path = self.path.split("?")[0]

            if path == "/api/v1/upload":
                state["uploads"].append(body)
                self._respond(200, {
                    "file_id": "remote-file-001",
                    "original_name": "test.bin",
                    "size": len(body),
                    "path": "/uploads/remote-file-001",
                })
            elif "/rpc" in path:
                rpc = json.loads(body) if body else {}
                self._respond(200, {
                    "jsonrpc": "2.0",
                    "id": rpc.get("id", 1),
                    "result": {"ok": True, "method": rpc.get("method")},
                })
            else:
                self._respond(404, {"error": "Not found"})

        def _respond(self, status, data):
            body = json.dumps(data).encode()
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


def test_remote_upload_and_rpc(mock_gw, tmp_path):
    """Upload → RPC → verify."""
    url, state = mock_gw
    test_file = tmp_path / "sample.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 50)

    result = upload_binary(url, str(test_file))
    assert result["file_id"] == "remote-file-001"
    assert len(state["uploads"]) == 1

    rpc_result = post_rpc_remote(url, "inst1", "decompile", {"addr": "0x401000"})
    assert rpc_result["ok"] is True


def test_remote_list_instances(mock_gw):
    url, state = mock_gw
    state["instances"] = [
        {"id": "ida_001", "engine": "ida", "state": "ready"},
    ]
    instances = remote_list(url)
    assert len(instances) == 1
    assert instances[0]["engine"] == "ida"


def test_remote_rpc_forward(mock_gw):
    url, _ = mock_gw
    result = post_rpc_remote(url, "test_inst", "get_classes")
    assert result["method"] == "get_classes"
