"""Tests for gateway/audit.py."""

import json
import os
import threading
from pathlib import Path

import pytest

from revkit.tools.gateway.audit import GatewayAuditLogger, _redact_params


def test_jsonl_format(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path)
    logger.log_request("GET", "/api/v1/health", 200, "127.0.0.1", 1.5)

    lines = audit_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["method"] == "GET"
    assert record["path"] == "/api/v1/health"
    assert record["status"] == 200


def test_source_ip(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path)
    logger.log_request("POST", "/api/v1/upload", 200, "10.0.0.5", 42.0)

    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["source_ip"] == "10.0.0.5"


def test_elapsed_ms(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path)
    logger.log_request("POST", "/rpc", 200, "127.0.0.1", 123.456)

    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["elapsed_ms"] == 123.46


def test_redaction():
    params = {"code": "evil_code", "method": "decompile", "addr": "0x401000"}
    redacted = _redact_params(params)
    assert redacted["code"] == "[REDACTED]"
    assert redacted["method"] == "decompile"
    assert redacted["addr"] == "0x401000"


def test_log_rpc_params_enabled(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path, log_rpc_params=True)
    logger.log_request(
        "POST", "/rpc", 200, "127.0.0.1", 1.0,
        rpc_method="exec",
        params={"code": "secret", "arg": "visible"},
    )
    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["params"]["code"] == "[REDACTED]"
    assert record["params"]["arg"] == "visible"


def test_log_rpc_params_disabled(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path, log_rpc_params=False)
    logger.log_request(
        "POST", "/rpc", 200, "127.0.0.1", 1.0,
        params={"code": "secret"},
    )
    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert "params" not in record


def test_thread_safety(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path)

    def write_n(n):
        for i in range(n):
            logger.log_request("GET", f"/thread/{n}", 200, "127.0.0.1", float(i))

    threads = [threading.Thread(target=write_n, args=(i,)) for i in range(1, 11)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = audit_path.read_text(encoding="utf-8").strip().split("\n")
    total_expected = sum(range(1, 11))
    assert len(lines) == total_expected
    for line in lines:
        json.loads(line)  # all valid JSON


def test_io_failure_silent(tmp_path):
    """Logger should not raise on I/O failure."""
    logger = GatewayAuditLogger(audit_path="/nonexistent/dir/audit.jsonl")
    # Should not raise
    logger.log_request("GET", "/test", 500, "127.0.0.1", 1.0)


def test_archive_rotation(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path, max_size_mb=0.0001)

    for i in range(100):
        logger.log_request("GET", "/test", 200, "127.0.0.1", float(i))

    archive_files = list(tmp_path.glob("audit_*.jsonl"))
    assert len(archive_files) >= 1


def test_api_key_id_field(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = GatewayAuditLogger(audit_path=audit_path)
    logger.log_request(
        "POST", "/rpc", 200, "127.0.0.1", 1.0,
        api_key_id="abc12345...",
    )
    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["api_key_id"] == "abc12345..."
