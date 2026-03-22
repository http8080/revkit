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
    with open(file_path, "rb") as f:
        file_data = f.read()

    body = bytearray()
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += file_data
    body += f"\r\n--{boundary}--\r\n".encode()

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=bytes(body), headers=headers, method="POST")

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
