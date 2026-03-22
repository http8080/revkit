"""Shared test fixtures for revkit."""

import json
import os
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest


@pytest.fixture
def tmp_registry(tmp_path):
    """Temporary registry path (prevents touching ~/.revkit/)."""
    return tmp_path / "registry.json"


@pytest.fixture
def sample_config(tmp_path):
    """Create a minimal config.json and return its path."""
    cfg = {
        "data_dir": str(tmp_path / "data"),
        "ida": {
            "install_dir": str(tmp_path / "ida"),
            "analysis": {
                "max_instances": 3,
                "stale_threshold": 120,
                "request_timeout": 60,
                "request_timeout_batch": 300,
            },
        },
        "jeb": {
            "install_dir": str(tmp_path / "jeb"),
            "java_home": str(tmp_path / "java"),
            "heap": {"auto": False, "default": "4G"},
            "analysis": {
                "max_instances": 3,
                "stale_threshold": 120,
                "request_timeout": 60,
                "request_timeout_batch": 300,
            },
        },
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    return config_path


@pytest.fixture
def sample_binaries(tmp_path):
    """Create minimal test binaries (PE, ELF, APK header)."""
    bins = {}

    # Minimal PE
    pe_path = tmp_path / "test.exe"
    pe_path.write_bytes(b"MZ" + b"\x00" * 1022)
    bins["pe"] = pe_path

    # Minimal ELF
    elf_path = tmp_path / "test.so"
    elf_path.write_bytes(b"\x7fELF" + b"\x00" * 1020)
    bins["elf"] = elf_path

    # Minimal APK (PK header)
    apk_path = tmp_path / "test.apk"
    apk_path.write_bytes(b"PK\x03\x04" + b"\x00" * 1020)
    bins["apk"] = apk_path

    # Minimal DEX
    dex_path = tmp_path / "classes.dex"
    dex_path.write_bytes(b"dex\n035\x00" + b"\x00" * 1016)
    bins["dex"] = dex_path

    # Non-binary text file
    txt_path = tmp_path / "readme.txt"
    txt_path.write_text("hello")
    bins["txt"] = txt_path

    return bins


@pytest.fixture
def mock_rpc_server():
    """Start a mock JSON-RPC server on a random port. Yields (host, port)."""
    responses = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            method = body.get("method", "")
            if method in responses:
                result = responses[method]
            else:
                result = {"result": {"ok": True, "method": method}}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    host, port = server.server_address
    yield host, port, responses

    server.shutdown()
