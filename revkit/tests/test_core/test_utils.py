"""Tests for core/utils.py."""

from revkit.tools.core.utils import file_md5, truncate


def test_file_md5(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"hello world")
    h = file_md5(f)
    assert h is not None
    assert len(h) == 32


def test_file_md5_missing():
    assert file_md5("/nonexistent/file.bin") is None


def test_truncate_short():
    assert truncate("hello", 10) == "hello"


def test_truncate_exact():
    assert truncate("12345", 5) == "12345"


def test_truncate_long():
    result = truncate("a" * 50, 10)
    assert len(result) == 10
    assert result.endswith("...")
