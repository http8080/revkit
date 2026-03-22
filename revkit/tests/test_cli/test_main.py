"""Tests for cli/main.py — Tier 1 commands + Phase 5a enhancements."""

import json
import sys
from types import SimpleNamespace

import pytest

from revkit.tools.cli.main import auto_detect_engine, build_parser, _write_output, main


def test_no_args():
    assert main([]) == 2


def test_engine_only():
    with pytest.raises(SystemExit):
        main(["ida"])


def test_build_parser():
    parser = build_parser()
    assert parser is not None


def test_list_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "revkit.tools.cli.commands.common.get_registry_path",
        lambda name: tmp_path / name / "registry.json",
    )
    # global options must come BEFORE the engine subcommand
    result = main(["--config", str(tmp_path / "nonexistent.json"), "ida", "list"])
    assert result == 0


def test_json_output_list(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "revkit.tools.cli.commands.common.get_registry_path",
        lambda name: tmp_path / name / "registry.json",
    )
    result = main(["--json", "--config", str(tmp_path / "noconfig.json"), "ida", "list"])
    assert result == 0
    captured = capsys.readouterr()
    if captured.out.strip():
        data = json.loads(captured.out)
        assert data["ok"] is True


# ── Phase 5a: auto_detect_engine tests ──────────────────

def test_auto_detect_exe(sample_binaries):
    engine = auto_detect_engine(str(sample_binaries["pe"]))
    assert engine.engine_name == "ida"


def test_auto_detect_elf(sample_binaries):
    engine = auto_detect_engine(str(sample_binaries["elf"]))
    assert engine.engine_name == "ida"


def test_auto_detect_apk(sample_binaries):
    engine = auto_detect_engine(str(sample_binaries["apk"]))
    assert engine.engine_name == "jeb"


def test_auto_detect_dex(sample_binaries):
    engine = auto_detect_engine(str(sample_binaries["dex"]))
    assert engine.engine_name == "jeb"


def test_auto_detect_unknown(tmp_path):
    txt = tmp_path / "readme.txt"
    txt.write_text("hello")
    with pytest.raises(ValueError):
        auto_detect_engine(str(txt))


# ── Phase 5a: _write_output tests ───────────────────────

def test_write_output_dict(tmp_path):
    args = SimpleNamespace(out=str(tmp_path / "result.json"))
    _write_output(args, {"key": "value"})
    assert (tmp_path / "result.json").exists()
    data = json.loads((tmp_path / "result.json").read_text())
    assert data["key"] == "value"


def test_write_output_str(tmp_path):
    args = SimpleNamespace(out=str(tmp_path / "result.txt"))
    _write_output(args, "hello world")
    assert (tmp_path / "result.txt").read_text(encoding="utf-8") == "hello world"


def test_write_output_none(tmp_path):
    args = SimpleNamespace(out=None)
    _write_output(args, {"key": "value"})
    # no file should be created


def test_write_output_no_attr():
    args = SimpleNamespace()
    _write_output(args, {"key": "value"})


# ── Phase 5a: parser --out and --remote options ─────────

def test_parser_has_out_option():
    parser = build_parser()
    args = parser.parse_args(["--out", "/tmp/test.json", "ida", "list"])
    assert args.out == "/tmp/test.json"


def test_parser_has_remote_option():
    parser = build_parser()
    args = parser.parse_args(["--remote", "http://host:8080", "ida", "list"])
    assert args.remote == "http://host:8080"
