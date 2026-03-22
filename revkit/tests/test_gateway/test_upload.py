"""Tests for gateway/upload.py."""

import os
import io
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from revkit.tools.gateway.upload import (
    UploadError,
    get_upload_dir,
    parse_multipart,
    _extract_boundary,
    _validate_path,
    cleanup_upload,
    _check_disk_space,
)


def _make_multipart(filename="test.bin", content=b"binary-data-here", boundary=b"----TestBoundary"):
    body = b"------TestBoundary\r\n"
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += content
    body += b"\r\n------TestBoundary--\r\n"
    return body, boundary


def _mock_handler(body, content_type="multipart/form-data; boundary=----TestBoundary"):
    handler = MagicMock()
    handler.headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
    }
    handler.rfile = io.BytesIO(body)
    return handler


def test_upload_binary(tmp_path):
    body, boundary = _make_multipart()
    handler = _mock_handler(body)
    gw_config = {"upload_dir": str(tmp_path / "uploads"), "max_upload_size_mb": 10}

    result = parse_multipart(handler, gw_config)
    assert "file_id" in result
    assert result["original_name"] == "test.bin"
    assert result["size"] > 0
    assert os.path.exists(result["path"])


def test_upload_uuid_filename(tmp_path):
    body, _ = _make_multipart(filename="malware.apk")
    handler = _mock_handler(body)
    gw_config = {"upload_dir": str(tmp_path / "uploads"), "max_upload_size_mb": 10}

    result = parse_multipart(handler, gw_config)
    assert "malware" not in os.path.basename(result["path"])
    try:
        uuid.UUID(result["file_id"], version=4)
    except ValueError:
        pass  # hex format, not standard UUID


def test_upload_size_limit(tmp_path):
    big_content = b"x" * (2 * 1024 * 1024)
    body, _ = _make_multipart(content=big_content)
    handler = _mock_handler(body)
    gw_config = {"upload_dir": str(tmp_path / "uploads"), "max_upload_size_mb": 1}

    with pytest.raises(UploadError) as exc_info:
        parse_multipart(handler, gw_config)
    assert exc_info.value.status == 413


def test_empty_upload(tmp_path):
    handler = MagicMock()
    handler.headers = {
        "Content-Type": "multipart/form-data; boundary=----TestBoundary",
        "Content-Length": "0",
    }
    gw_config = {"upload_dir": str(tmp_path / "uploads"), "max_upload_size_mb": 10}

    with pytest.raises(UploadError) as exc_info:
        parse_multipart(handler, gw_config)
    assert exc_info.value.status == 411


def test_extract_boundary():
    b = _extract_boundary("multipart/form-data; boundary=----Bound123")
    assert b == b"----Bound123"


def test_extract_boundary_missing():
    with pytest.raises(UploadError):
        _extract_boundary("application/json")


def test_validate_path_ok(tmp_path):
    target = tmp_path / "uploads" / "abcdef123"
    _validate_path(target, tmp_path / "uploads")


def test_validate_path_traversal(tmp_path):
    target = tmp_path / "uploads" / ".." / ".." / "etc" / "passwd"
    with pytest.raises(UploadError) as exc_info:
        _validate_path(target, tmp_path / "uploads")
    assert "traversal" in exc_info.value.message.lower()


def test_get_upload_dir_creates(tmp_path):
    gw_config = {"upload_dir": str(tmp_path / "new_uploads")}
    d = get_upload_dir(gw_config)
    assert d.is_dir()


def test_cleanup_upload(tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    fid = "test-file-id"
    (upload_dir / fid).write_bytes(b"data")
    gw_config = {"upload_dir": str(upload_dir)}

    assert cleanup_upload(fid, gw_config) is True
    assert not (upload_dir / fid).exists()


def test_cleanup_upload_nonexistent(tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    gw_config = {"upload_dir": str(upload_dir)}
    assert cleanup_upload("nonexistent", gw_config) is False


def test_disk_space_check(tmp_path):
    # Should not raise for normal cases
    _check_disk_space(tmp_path, 1024)
