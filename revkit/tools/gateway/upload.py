"""revkit gateway — file upload handler.

Parses multipart/form-data, saves with UUID filename,
enforces size limits, and uses atomic writes.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MAX_UPLOAD_MB = 500
STREAM_CHUNK_SIZE = 65536


class UploadError(Exception):
    """Upload processing error with HTTP status code."""

    def __init__(self, message: str, status: int = 400):
        self.message = message
        self.status = status
        super().__init__(message)


def get_upload_dir(gw_config: dict) -> Path:
    """Get or create the upload directory."""
    upload_dir = gw_config.get("upload_dir")
    if upload_dir:
        p = Path(upload_dir)
    else:
        p = Path.home() / ".revkit" / "uploads"
    p.mkdir(parents=True, exist_ok=True)
    return p


def parse_multipart(handler, gw_config: dict) -> dict:
    """Parse multipart upload request and save file atomically.

    Returns:
        dict with file_id, original_name, size, path
    """
    max_size_mb = gw_config.get("max_upload_size_mb", DEFAULT_MAX_UPLOAD_MB)
    if max_size_mb is None:
        raise UploadError("Upload is disabled (max_upload_size_mb is null)", 403)
    unlimited = (max_size_mb == 0)
    max_size = int(max_size_mb * 1024 * 1024) if not unlimited else 0
    upload_dir = get_upload_dir(gw_config)
    log.debug("parse_multipart: upload_dir=%s max_size=%s",
              upload_dir, "unlimited" if unlimited else f"{max_size_mb}MB")

    content_length = int(handler.headers.get("Content-Length", 0))
    if content_length <= 0:
        raise UploadError("Missing Content-Length header", 411)
    if not unlimited and content_length > max_size:
        raise UploadError(
            f"File too large: {content_length} bytes (max {max_size_mb}MB)", 413
        )
    if not unlimited:
        _check_disk_space(upload_dir, max_size)

    content_type = handler.headers.get("Content-Type", "")
    boundary = _extract_boundary(content_type)

    file_id = uuid.uuid4().hex
    tmp_path = None

    try:
        original_name, tmp_path, file_size = _stream_multipart(
            handler.rfile, boundary, content_length, max_size, upload_dir, file_id
        )

        final_path = upload_dir / file_id
        _validate_path(final_path, upload_dir)
        os.rename(str(tmp_path), str(final_path))
        tmp_path = None

        log.debug("parse_multipart: saved file_id=%s name=%s size=%d path=%s",
                  file_id, original_name, file_size, final_path)
        return {
            "file_id": file_id,
            "original_name": original_name,
            "size": file_size,
            "path": str(final_path),
        }
    finally:
        if tmp_path and os.path.exists(str(tmp_path)):
            try:
                os.remove(str(tmp_path))
            except OSError:
                pass


def _extract_boundary(content_type: str) -> bytes:
    """Extract multipart boundary from Content-Type header."""
    match = re.search(r'boundary="?([^"\s;]+)"?', content_type)  # L19: handle quoted boundary
    if not match:
        raise UploadError("Missing multipart boundary", 400)
    return match.group(1).encode("ascii")


def _stream_multipart(
    rfile,
    boundary: bytes,
    content_length: int,
    max_size: int,
    upload_dir: Path,
    file_id: str,
) -> tuple[str, Path, int]:
    """Stream multipart body to disk incrementally.

    Reads chunks from rfile and writes directly to temp file,
    avoiding loading entire upload into memory (~70MB peak vs 1.2GB).

    Returns (original_name, tmp_path, file_size).
    """
    delimiter = b"--" + boundary
    end_delimiter = delimiter + b"--"

    # Phase 1: Read headers to find filename (small, <8KB typically)
    # We need to find the \r\n\r\n boundary between headers and body
    header_buf = b""
    original_name = "unknown"
    body_start_offset = 0

    # Read enough to get past boundary + headers (usually <4KB)
    initial_chunk = rfile.read(min(STREAM_CHUNK_SIZE, content_length))
    remaining = content_length - len(initial_chunk)

    # Find the file part header
    delim_pos = initial_chunk.find(delimiter)
    if delim_pos == -1:
        raise UploadError("No multipart boundary found", 400)

    # Skip past boundary + CRLF
    header_start = delim_pos + len(delimiter)
    if initial_chunk[header_start:header_start + 2] == b"\r\n":
        header_start += 2
    elif initial_chunk[header_start:header_start + 1] == b"\n":
        header_start += 1

    # Find end of headers
    header_end = initial_chunk.find(b"\r\n\r\n", header_start)
    body_sep_len = 4
    if header_end == -1:
        header_end = initial_chunk.find(b"\n\n", header_start)
        body_sep_len = 2
    if header_end == -1:
        raise UploadError("Malformed multipart: no header/body separator", 400)

    headers_str = initial_chunk[header_start:header_end].decode("utf-8", errors="replace")
    fname_match = re.search(r'filename="([^"]*)"', headers_str)
    if fname_match:
        original_name = os.path.basename(fname_match.group(1))

    # Phase 2: Stream body to temp file
    body_offset = header_end + body_sep_len
    leftover = initial_chunk[body_offset:]

    tmp_path = upload_dir / f"{file_id}.tmp"
    file_size = 0

    with open(str(tmp_path), "wb") as f:
        # Write initial leftover
        f.write(leftover)
        file_size += len(leftover)

        # Stream remaining data in chunks
        while remaining > 0:
            chunk_size = min(STREAM_CHUNK_SIZE, remaining)
            chunk = rfile.read(chunk_size)
            if not chunk:
                break
            remaining -= len(chunk)
            f.write(chunk)
            file_size += len(chunk)

            if max_size > 0 and file_size > max_size:
                raise UploadError(
                    f"File too large: >{file_size} bytes (max {max_size // (1024*1024)}MB)",
                    413,
                )

    # Phase 3: Trim trailing boundary from file
    # The file now contains: <body>\r\n--boundary--\r\n
    # We need to strip the trailing delimiter
    trail_len = len(end_delimiter) + 8  # generous: \r\n + end_delimiter + \r\n + padding
    with open(str(tmp_path), "r+b") as f:
        actual_size = f.seek(0, 2)  # seek to end
        read_back = min(trail_len, actual_size)
        f.seek(actual_size - read_back)
        tail = f.read(read_back)

        # Find the last boundary in the tail
        end_pos = tail.rfind(delimiter)
        if end_pos != -1:
            # Check for preceding \r\n
            trim_start = end_pos
            if trim_start >= 2 and tail[trim_start - 2:trim_start] == b"\r\n":
                trim_start -= 2
            elif trim_start >= 1 and tail[trim_start - 1:trim_start] == b"\n":
                trim_start -= 1
            new_size = actual_size - read_back + trim_start
            f.truncate(new_size)
            file_size = new_size

    return original_name, tmp_path, file_size


def _check_disk_space(upload_dir: Path, required_bytes: int) -> None:
    """Check if sufficient disk space is available."""
    try:
        usage = shutil.disk_usage(str(upload_dir))
        if usage.free < required_bytes * 2:
            raise UploadError(
                f"Insufficient disk space: {usage.free // (1024*1024)}MB free, "
                f"need ~{required_bytes * 2 // (1024*1024)}MB",
                507,
            )
    except OSError:
        pass


def _validate_path(target: Path, base_dir: Path) -> None:
    """Prevent path traversal by verifying target is under base_dir."""
    real_target = os.path.realpath(str(target))
    real_base = os.path.realpath(str(base_dir))
    if not real_target.startswith(real_base):
        raise UploadError("Path traversal detected", 400)


def cleanup_upload(file_id: str, gw_config: dict) -> bool:
    """Remove an uploaded file by ID. Returns True if deleted."""
    upload_dir = get_upload_dir(gw_config)
    target = upload_dir / file_id
    _validate_path(target, upload_dir)
    try:
        os.remove(str(target))
        return True
    except OSError:
        return False
