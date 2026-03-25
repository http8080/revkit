"""revkit CLI — remote mode (Gateway API client).

Provides upload_binary(), post_rpc_remote(), and remote_start()
for communicating with a revkit Gateway server.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from ..core.output import log_err, log_info, log_ok, log_verbose


def post_rpc_remote(
    gateway_url: str,
    instance_id: str,
    method: str,
    params: dict | None = None,
    api_key: str | None = None,
    timeout: float = 60,
) -> dict:
    """Send JSON-RPC request via Gateway proxy.

    Args:
        gateway_url: Gateway base URL (e.g. http://srv:8080)
        instance_id: Target engine instance ID
        method: RPC method name
        params: RPC parameters
        api_key: Gateway API key (Bearer token)
        timeout: Request timeout in seconds

    Returns:
        RPC result dict
    """
    url = f"{gateway_url.rstrip('/')}/api/v1/instances/{instance_id}/rpc"
    rpc_body = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": 1,
    }
    data = json.dumps(rpc_body).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
            if "error" in result:
                raise RuntimeError(
                    f"RPC error: {result['error'].get('message', result['error'])}"
                )
            return result.get("result", result)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gateway HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Gateway unreachable: {e}") from e


class _StreamingUploadBody:
    """File-like wrapper that streams multipart body without loading file into memory.

    Peak memory: ~128KB instead of 2x file size.
    """
    _CHUNK = 65536

    def __init__(self, file_path: str, boundary: str, filename: str):
        self._file_path = file_path
        self._preamble = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        self._epilogue = f"\r\n--{boundary}--\r\n".encode()
        file_size = os.path.getsize(file_path)
        self._total = len(self._preamble) + file_size + len(self._epilogue)
        self._pos = 0
        self._file = None
        self._phase = 0  # 0=preamble, 1=file, 2=epilogue, 3=done
        self._epi_pos = 0

    def __len__(self):
        return self._total

    def read(self, size=-1):
        if size == -1:
            size = self._total - self._pos
        result = b""
        while len(result) < size and self._phase < 3:
            remaining = size - len(result)
            if self._phase == 0:
                chunk = self._preamble[self._pos:self._pos + remaining]
                result += chunk
                self._pos += len(chunk)
                if self._pos >= len(self._preamble):
                    self._phase = 1
                    self._file = open(self._file_path, "rb")
            elif self._phase == 1:
                chunk = self._file.read(min(remaining, self._CHUNK))
                if not chunk:
                    self._file.close()
                    self._file = None
                    self._phase = 2
                    continue
                result += chunk
                self._pos += len(chunk)
            elif self._phase == 2:
                chunk = self._epilogue[self._epi_pos:self._epi_pos + remaining]
                result += chunk
                self._pos += len(chunk)
                self._epi_pos += len(chunk)
                if self._epi_pos >= len(self._epilogue):
                    self._phase = 3
        return result

    def close(self):
        if self._file:
            self._file.close()
            self._file = None


def upload_binary(
    gateway_url: str,
    file_path: str,
    api_key: str | None = None,
    timeout: float = 300,
) -> dict:
    """Upload a binary file to Gateway via multipart/form-data.

    Args:
        gateway_url: Gateway base URL
        file_path: Local path to binary file
        api_key: Gateway API key
        timeout: Upload timeout

    Returns:
        dict with file_id, original_name, size, path
    """
    url = f"{gateway_url.rstrip('/')}/api/v1/upload"
    file_path = str(Path(file_path).resolve())
    filename = os.path.basename(file_path).replace('"', '_')  # M15: escape quotes

    boundary = uuid.uuid4().hex
    body = _StreamingUploadBody(file_path, boundary, filename)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
            if "error" in result:
                raise RuntimeError(f"Upload failed: {result['error']}")
            log_ok(f"Uploaded {filename} → file_id={result.get('file_id')}")
            return result
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Upload HTTP {e.code}: {body_text}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Gateway unreachable: {e}") from e
    finally:
        body.close()


def remote_start(
    gateway_url: str,
    engine_name: str,
    file_path: str,
    api_key: str | None = None,
    poll_interval: float = 2.0,
    timeout: float = 120.0,
    fresh: bool = False,
    force: bool = False,
    xmx: str | None = None,
) -> dict:
    """Remote start: upload → start → wait → ready.

    Args:
        gateway_url: Gateway base URL
        engine_name: Engine name (ida/jeb)
        file_path: Local binary path
        api_key: Gateway API key
        poll_interval: Polling interval in seconds
        timeout: Total timeout for the operation

    Returns:
        dict with instance_id, file_id
    """
    upload_result = upload_binary(gateway_url, file_path, api_key)
    file_id = upload_result["file_id"]

    url = f"{gateway_url.rstrip('/')}/api/v1/engines/{engine_name}/start"
    original_name = upload_result.get("original_name", os.path.basename(file_path))
    start_params = {
        "file_id": file_id,
        "original_name": original_name,
    }
    if fresh:
        start_params["fresh"] = True
    if force:
        start_params["force"] = True
    if xmx:
        start_params["xmx"] = xmx
    start_body = json.dumps(start_params).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=start_body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # L18: use timeout param
            result = json.loads(resp.read())
            if "error" in result:
                raise RuntimeError(f"Start failed: {result['error']}")
            instance_id = result.get("instance_id")
            log_info(f"Remote start requested: {instance_id}")
            return {"instance_id": instance_id, "file_id": file_id, **result}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Start HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Gateway unreachable: {e}") from e


def remote_list(
    gateway_url: str,
    api_key: str | None = None,
    timeout: float = 30,
) -> list[dict]:
    """List instances via Gateway API.

    Returns:
        List of instance dicts
    """
    url = f"{gateway_url.rstrip('/')}/api/v1/instances"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
            return result.get("instances", [])
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"List HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Gateway unreachable: {e}") from e
