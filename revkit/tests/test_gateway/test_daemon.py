"""Tests for gateway/daemon.py."""

import json
import threading
import urllib.request
import urllib.error

import pytest

from revkit.tools.gateway.daemon import GatewayDaemon, GatewayHandler
from revkit.tools.gateway.config import validate_gateway_config


def _get(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def _get_with_auth(url, api_key):
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def test_start_stop(gw_config):
    server = GatewayDaemon(gw_config)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    status, data = _get(f"http://{host}:{port}/api/v1/health")
    assert status == 200
    assert data["status"] == "ok"
    server.shutdown()


def test_health_endpoint(gateway_server):
    host, port, _ = gateway_server
    status, data = _get(f"http://{host}:{port}/api/v1/health")
    assert status == 200
    assert data["service"] == "revkit-gateway"
    assert "timestamp" in data


def test_health_no_auth_required(gateway_server):
    """Health endpoint should be accessible without API key."""
    host, port, cfg = gateway_server
    status, data = _get(f"http://{host}:{port}/api/v1/health")
    assert status == 200


def test_auth_required_for_protected(gateway_server):
    """Non-public paths require auth when api_key is set."""
    host, port, cfg = gateway_server
    try:
        _get(f"http://{host}:{port}/api/v1/instances")
        assert False, "Should have raised HTTPError"
    except urllib.error.HTTPError as e:
        assert e.code == 403


def test_auth_with_valid_key(gateway_server):
    host, port, cfg = gateway_server
    status, data = _get_with_auth(
        f"http://{host}:{port}/api/v1/instances",
        cfg["api_key"],
    )
    assert status == 200


def test_invalid_config():
    errors = validate_gateway_config({"port": 99999})
    assert any("port" in e.lower() or "Port" in e for e in errors)


def test_bind_address(gw_config):
    gw_config["host"] = "127.0.0.1"
    server = GatewayDaemon(gw_config)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    assert host == "127.0.0.1"
    server.shutdown()


def test_daemon_health_method(gw_config):
    server = GatewayDaemon(gw_config)
    health = server.health()
    assert health["status"] == "running"
    server.server_close()


def test_unknown_endpoint(gateway_server):
    host, port, cfg = gateway_server
    try:
        _get_with_auth(
            f"http://{host}:{port}/api/v1/nonexistent",
            cfg["api_key"],
        )
        assert False, "Should have raised HTTPError"
    except urllib.error.HTTPError as e:
        assert e.code == 404
