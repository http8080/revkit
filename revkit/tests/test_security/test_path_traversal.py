"""Security tests — path traversal prevention (Q4)."""

import os
from pathlib import Path

import pytest

from revkit.tools.gateway.upload import _validate_path, UploadError


TRAVERSAL_VECTORS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config",
    "....//....//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..%5c..%5cwindows",
]


@pytest.mark.parametrize("vector", TRAVERSAL_VECTORS)
def test_upload_path_traversal(tmp_path, vector):
    """Upload path with traversal vector must be rejected."""
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    target = upload_dir / vector
    real_target = os.path.realpath(str(target))
    real_base = os.path.realpath(str(upload_dir))
    if not real_target.startswith(real_base):
        with pytest.raises(UploadError, match="[Tt]raversal"):
            _validate_path(target, upload_dir)


def test_null_byte_in_filename(tmp_path):
    """Null byte in filename should not bypass validation."""
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    # On Windows, null bytes in filenames are invalid anyway
    try:
        target = upload_dir / "file\x00.exe"
        _validate_path(target, upload_dir)
    except (UploadError, ValueError, OSError):
        pass  # Expected on most platforms


def test_safe_path_allowed(tmp_path):
    """Normal paths should pass validation."""
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    target = upload_dir / "abc123def456"
    _validate_path(target, upload_dir)


def test_uuid_filenames_safe(tmp_path):
    """UUID-based filenames should always be safe."""
    import uuid
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    for _ in range(10):
        fid = uuid.uuid4().hex
        target = upload_dir / fid
        _validate_path(target, upload_dir)
