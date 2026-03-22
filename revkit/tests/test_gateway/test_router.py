"""Tests for gateway/router.py."""

import json
import threading
import urllib.request
import urllib.error

import pytest

from revkit.tools.gateway.daemon import GatewayDaemon
from revkit.tools.gateway.router import (
    COMPILED_ROUTES,
    handle_health,
    _find_instance,
)


def _request(method, url, data=None, api_key=None, timeout=5):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_health_route(gateway_server):
    host, port, cfg = gateway_server
    status, data = _request("GET", f"http://{host}:{port}/api/v1/health")
    assert status == 200
    assert data["status"] == "ok"


def test_list_instances_empty(gateway_server, tmp_path, monkeypatch):
    host, port, cfg = gateway_server
    monkeypatch.setattr(
        "revkit.tools.core.registry.get_registry_path",
        lambda name: tmp_path / name / "registry.json",
    )
    status, data = _request(
        "GET", f"http://{host}:{port}/api/v1/instances",
        api_key=cfg["api_key"],
    )
    assert status == 200
    assert data["instances"] == []


def test_rpc_proxy_no_instance(gateway_server):
    host, port, cfg = gateway_server
    status, data = _request(
        "POST",
        f"http://{host}:{port}/api/v1/instances/nonexistent/rpc",
        data={"jsonrpc": "2.0", "method": "test", "id": 1},
        api_key=cfg["api_key"],
    )
    assert status == 404


def test_rpc_proxy_forward(gateway_server, mock_engine_server, monkeypatch):
    host, port, cfg = gateway_server
    eng_host, eng_port, _ = mock_engine_server

    fake_instance = {
        "id": "test_inst",
        "port": eng_port,
        "auth_token": None,
    }
    monkeypatch.setattr(
        "revkit.tools.gateway.router._find_instance",
        lambda iid: fake_instance if iid == "test_inst" else None,
    )

    status, data = _request(
        "POST",
        f"http://{host}:{port}/api/v1/instances/test_inst/rpc",
        data={"jsonrpc": "2.0", "method": "decompile", "id": 1},
        api_key=cfg["api_key"],
    )
    assert status == 200
    assert data.get("result", {}).get("ok") is True


def test_delete_instance_not_found(gateway_server, tmp_path, monkeypatch):
    host, port, cfg = gateway_server
    monkeypatch.setattr(
        "revkit.tools.core.registry.get_registry_path",
        lambda name: tmp_path / name / "registry.json",
    )
    status, data = _request(
        "DELETE",
        f"http://{host}:{port}/api/v1/instances/nonexistent",
        api_key=cfg["api_key"],
    )
    assert status == 404


def test_start_engine_unknown(gateway_server):
    host, port, cfg = gateway_server
    status, data = _request(
        "POST",
        f"http://{host}:{port}/api/v1/engines/ghidra/start",
        data={"binary": "test.exe"},
        api_key=cfg["api_key"],
    )
    assert status == 400


def test_start_engine_not_implemented(gateway_server):
    host, port, cfg = gateway_server
    status, data = _request(
        "POST",
        f"http://{host}:{port}/api/v1/engines/ida/start",
        data={"binary": "test.exe"},
        api_key=cfg["api_key"],
    )
    assert status == 501


def test_unknown_endpoint_404(gateway_server):
    host, port, cfg = gateway_server
    status, data = _request(
        "GET",
        f"http://{host}:{port}/api/v1/nonexistent",
        api_key=cfg["api_key"],
    )
    assert status == 404


def test_upload_progress_stub(gateway_server):
    host, port, cfg = gateway_server
    status, data = _request(
        "GET",
        f"http://{host}:{port}/api/v1/upload-progress/abc123",
        api_key=cfg["api_key"],
    )
    assert status == 200
    assert data["file_id"] == "abc123"


def test_batch_timeout_detection(gateway_server, mock_engine_server, monkeypatch):
    """Batch RPC requests should use longer timeout."""
    host, port, cfg = gateway_server
    eng_host, eng_port, _ = mock_engine_server

    fake_instance = {"id": "batch_inst", "port": eng_port, "auth_token": None}
    monkeypatch.setattr(
        "revkit.tools.gateway.router._find_instance",
        lambda iid: fake_instance if iid == "batch_inst" else None,
    )

    status, data = _request(
        "POST",
        f"http://{host}:{port}/api/v1/instances/batch_inst/rpc",
        data={
            "jsonrpc": "2.0",
            "method": "batch_decompile",
            "params": {"is_batch": True},
            "id": 1,
        },
        api_key=cfg["api_key"],
    )
    assert status == 200


def test_compiled_routes_exist():
    assert len(COMPILED_ROUTES) >= 7
    methods = [r[0] for r in COMPILED_ROUTES]
    assert "GET" in methods
    assert "POST" in methods
    assert "DELETE" in methods
