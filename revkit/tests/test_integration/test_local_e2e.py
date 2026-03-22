"""Local end-to-end tests (mocked engine processes)."""

import json
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from revkit.tools.cli.main import main, build_parser, auto_detect_engine


def test_cli_start_args():
    """Parser correctly parses start arguments."""
    parser = build_parser()
    args = parser.parse_args(["ida", "start", "test.exe"])
    assert args.engine == "ida"
    assert args.command == "start"
    assert args.binary == "test.exe"


def test_cli_list_args():
    parser = build_parser()
    args = parser.parse_args(["jeb", "list"])
    assert args.engine == "jeb"
    assert args.command == "list"


def test_cli_stop_args():
    parser = build_parser()
    args = parser.parse_args(["ida", "stop", "-i", "abc123"])
    assert args.instance == "abc123"


def test_cli_json_flag():
    parser = build_parser()
    args = parser.parse_args(["--json", "ida", "list"])
    assert args.json_mode is True


def test_cli_out_flag():
    parser = build_parser()
    args = parser.parse_args(["--out", "result.json", "ida", "list"])
    assert args.out == "result.json"


def test_cli_remote_flag():
    parser = build_parser()
    args = parser.parse_args(["--remote", "http://srv:8080", "ida", "list"])
    assert args.remote == "http://srv:8080"


def test_auto_detect_pe(tmp_path):
    pe = tmp_path / "test.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 100)
    engine = auto_detect_engine(str(pe))
    assert engine.engine_name == "ida"


def test_auto_detect_elf(tmp_path):
    elf = tmp_path / "test.so"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 100)
    engine = auto_detect_engine(str(elf))
    assert engine.engine_name == "ida"


def test_auto_detect_apk(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    engine = auto_detect_engine(str(apk))
    assert engine.engine_name == "jeb"


def test_auto_detect_dex(tmp_path):
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00" + b"\x00" * 100)
    engine = auto_detect_engine(str(dex))
    assert engine.engine_name == "jeb"


def test_auto_detect_unknown(tmp_path):
    txt = tmp_path / "notes.txt"
    txt.write_text("hello")
    with pytest.raises(ValueError):
        auto_detect_engine(str(txt))


def test_auto_detect_by_extension(tmp_path):
    dll = tmp_path / "lib.dll"
    dll.write_bytes(b"\x00" * 100)
    engine = auto_detect_engine(str(dll))
    assert engine.engine_name == "ida"


def test_list_empty_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "revkit.tools.cli.commands.common.get_registry_path",
        lambda name: tmp_path / name / "registry.json",
    )
    result = main(["--json", "--config", str(tmp_path / "no.json"), "ida", "list"])
    assert result == 0


def test_both_engines_list(tmp_path, monkeypatch, capsys):
    """List from both engines in sequence."""
    monkeypatch.setattr(
        "revkit.tools.cli.commands.common.get_registry_path",
        lambda name: tmp_path / name / "registry.json",
    )
    r1 = main(["--config", str(tmp_path / "no.json"), "ida", "list"])
    r2 = main(["--config", str(tmp_path / "no.json"), "jeb", "list"])
    assert r1 == 0
    assert r2 == 0
