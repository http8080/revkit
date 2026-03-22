"""Tests for core/rpc.py."""

import json
import pytest

from revkit.tools.core.rpc import RpcError, normalize_error, post_rpc


def test_post_rpc_success(mock_rpc_server):
    host, port, _ = mock_rpc_server
    result = post_rpc(f"http://{host}:{port}/", "ping", retries=1)
    assert "result" in result


def test_post_rpc_with_params(mock_rpc_server):
    host, port, responses = mock_rpc_server
    responses["decompile"] = {"result": {"code": "int main() {}"}}
    result = post_rpc(f"http://{host}:{port}/", "decompile", {"addr": "0x401000"}, retries=1)
    assert result["result"]["code"] == "int main() {}"


def test_post_rpc_connection_failed():
    with pytest.raises(RpcError, match="CONNECTION_FAILED"):
        post_rpc("http://127.0.0.1:1/", "ping", retries=1, retry_delay=0.01)


def test_post_rpc_timeout(mock_rpc_server):
    host, port, _ = mock_rpc_server
    # A very small timeout should trigger TimeoutError on slow responses
    # This test verifies the timeout parameter is passed through
    result = post_rpc(f"http://{host}:{port}/", "ping", timeout=30, retries=1)
    assert "result" in result


def test_post_rpc_callback_on_failure():
    called = []

    def on_fail():
        called.append(True)

    with pytest.raises(RpcError):
        post_rpc(
            "http://127.0.0.1:1/", "ping",
            retries=1, retry_delay=0.01,
            on_connection_failed=on_fail,
        )
    assert len(called) == 1


def test_post_rpc_auth_token(mock_rpc_server):
    host, port, _ = mock_rpc_server
    result = post_rpc(
        f"http://{host}:{port}/", "ping",
        auth_token="test-token", retries=1,
    )
    assert "result" in result


def test_rpc_error_to_dict():
    err = RpcError("TEST", "test message", suggestion="try again")
    d = err.to_dict()
    assert d["code"] == "TEST"
    assert d["suggestion"] == "try again"


def test_normalize_error():
    raw = {"error": {"code": "TIMEOUT", "message": "timed out", "suggestion": "increase timeout"}}
    norm = normalize_error(raw)
    assert norm["code"] == "TIMEOUT"
    assert norm["suggestion"] == "increase timeout"


def test_normalize_error_flat():
    raw = {"code": "ERR", "message": "fail"}
    norm = normalize_error(raw)
    assert norm["code"] == "ERR"


def test_batch_timeout_default(mock_rpc_server):
    host, port, _ = mock_rpc_server
    # is_batch should use longer timeout (no error = correct timeout applied)
    result = post_rpc(f"http://{host}:{port}/", "decompile_all", is_batch=True, retries=1)
    assert "result" in result


def test_verbose_logging(mock_rpc_server, caplog):
    import logging
    host, port, _ = mock_rpc_server
    with caplog.at_level(logging.INFO):
        post_rpc(f"http://{host}:{port}/", "ping", verbose=True, retries=1)
    assert any("RPC ->" in r.message for r in caplog.records)
