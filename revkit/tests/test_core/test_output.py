"""Tests for core/output.py."""

import revkit.tools.core.output as output


def test_set_output_mode():
    output.set_output_mode(quiet=True, verbose=False)
    assert output._quiet is True
    assert output._verbose is False
    output.set_output_mode(quiet=False, verbose=True)
    assert output.is_verbose() is True
    output.set_output_mode()


def test_json_success():
    resp = output.json_success("ida", "decompile", {"code": "main()"}, elapsed_ms=42.0)
    assert resp["ok"] is True
    assert resp["engine"] == "ida"
    assert resp["command"] == "decompile"
    assert resp["elapsed_ms"] == 42.0


def test_json_success_truncated():
    resp = output.json_success("jeb", "search", [], truncated=True)
    assert resp["truncated"] is True


def test_json_error():
    resp = output.json_error(
        "ida", "decompile", "TIMEOUT", "Request timed out",
        suggestion="Increase timeout",
    )
    assert resp["ok"] is False
    assert resp["error"]["code"] == "TIMEOUT"
    assert resp["error"]["suggestion"] == "Increase timeout"


def test_md_table_header():
    hdr = output.md_table_header("ID", "State", "PID")
    lines = hdr.split("\n")
    assert len(lines) == 2
    assert "ID" in lines[0]
    assert "---" in lines[1]


def test_log_functions(capsys):
    output.set_output_mode(quiet=False, verbose=True)
    output._json_mode = False
    output.log_ok("success")
    output.log_err("error")
    output.log_info("info")
    output.log_warn("warning")
    output.log_verbose("detail")
    captured = capsys.readouterr()
    assert "[+] success" in captured.out
    assert "[-] error" in captured.out
    assert "[.] detail" in captured.out
    output.set_output_mode()


def test_quiet_mode(capsys):
    output.set_output_mode(quiet=True)
    output._json_mode = False
    output.log_ok("should not appear")
    output.log_info("should not appear")
    output.log_err("should appear")
    captured = capsys.readouterr()
    assert "should not appear" not in captured.out
    assert "should appear" in captured.out
    output.set_output_mode()
