"""Tests for core/audit.py."""

import json
import threading

import pytest

from revkit.tools.core.audit import AuditLogger, get_audit_path


def test_get_audit_path():
    p = get_audit_path("ida")
    assert "ida" in str(p)
    assert p.name == "audit.jsonl"


def test_log_event(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log_event("ida", "decompile", "abc1", result_ok=True, elapsed_ms=42.5)
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["engine"] == "ida"
    assert record["cmd"] == "decompile"
    assert record["ok"] is True
    assert record["ms"] == 42.5


def test_redaction(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log_event("jeb", "exec", params={"code": "import os; os.system('rm -rf /')"})
    line = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert line["params"]["code"] == "[REDACTED]"


def test_thread_safety(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    threads = []
    for i in range(20):
        t = threading.Thread(
            target=logger.log_event,
            args=("ida", f"cmd_{i}", f"id_{i}"),
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 20
    for line in lines:
        json.loads(line)  # each line must be valid JSON


def test_io_failure_silent(tmp_path):
    """Audit logger should not raise on I/O failure."""
    logger = AuditLogger(tmp_path / "nonexistent" / "deep" / "audit.jsonl")
    # Should not raise — parent dirs auto-created
    logger.log_event("ida", "test")


def test_source_ip(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log_event("ida", "decompile", source_ip="192.168.1.1")
    record = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert record["source_ip"] == "192.168.1.1"
