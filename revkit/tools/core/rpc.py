"""revkit core — JSON-RPC client.

Sends JSON-RPC requests to engine servers (IDA/JEB).
Uses stdlib only (urllib) — no external dependencies.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Callable

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 600
DEFAULT_BATCH_TIMEOUT = 300
DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0


class RpcError(Exception):
    """Structured RPC error with code, message, and optional suggestion."""

    def __init__(
        self,
        code: str,
        message: str,
        suggestion: str | None = None,
        data: Any = None,
    ):
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.data = data
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.suggestion:
            d["suggestion"] = self.suggestion
        if self.data is not None:
            d["data"] = self.data
        return d


def normalize_error(raw: dict) -> dict:
    """Normalize an error dict to ``{code, message, suggestion}``."""
    if isinstance(raw.get("error"), dict):
        raw = raw["error"]
    return {
        "code": raw.get("code", "UNKNOWN"),
        "message": raw.get("message", str(raw)),
        "suggestion": raw.get("suggestion"),
    }


def post_rpc(
    url: str,
    method: str,
    params: dict | list | None = None,
    *,
    timeout: float | None = None,
    is_batch: bool = False,
    retries: int = DEFAULT_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    auth_token: str | None = None,
    verbose: bool = False,
    on_connection_failed: Callable | None = None,
    trace_id: str | None = None,
) -> dict:
    """Send a JSON-RPC request and return the parsed response.

    Args:
        url: Server endpoint (e.g. ``http://127.0.0.1:18861/``).
        method: RPC method name.
        params: Optional parameters.
        timeout: Request timeout in seconds.
        is_batch: Use longer batch timeout if *timeout* not specified.
        retries: Max retry attempts on connection failure.
        retry_delay: Seconds between retries.
        auth_token: Bearer token for Authorization header.
        verbose: Log request/response details.
        on_connection_failed: Callback invoked on final connection failure.

    Returns:
        Parsed JSON response dict.

    Raises:
        RpcError: on connection failure, timeout, or invalid response.
    """
    if timeout is None:
        timeout = DEFAULT_BATCH_TIMEOUT if is_batch else DEFAULT_TIMEOUT

    rpc_params = dict(params) if params else {}
    if trace_id:
        rpc_params["_trace_id"] = trace_id

    body = json.dumps(
        {"method": method, "params": rpc_params, "id": 1}
    ).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    if verbose:
        log.info("RPC -> %s (url=%s, timeout=%ss)", method, url, timeout)
        if params:
            log.info("  params: %s", json.dumps(params, ensure_ascii=False)[:200])

    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed = time.time() - t0
                raw = resp.read().decode("utf-8")
                if verbose:
                    log.info("RPC <- %s HTTP %s (%.2fs)", method, resp.status, elapsed)
                    log.info("  response: %s", raw[:300])
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    raise RpcError(
                        "INVALID_RESPONSE",
                        f"HTTP {resp.status}: {raw[:200]}",
                    )
        except urllib.error.URLError as e:
            last_err = e
            # Check if this is a timeout (wrapped as URLError on some platforms)
            if "timed out" in str(e).lower():
                raise RpcError("TIMEOUT", f"Request timeout ({timeout}s)")
            if attempt < retries - 1:
                delay = min(retry_delay * (2 ** attempt), 10.0)
                log.debug("RPC %s attempt %d/%d failed: %s, retrying in %.1fs",
                          method, attempt + 1, retries, e, delay)
                time.sleep(delay)
                continue

    if on_connection_failed:
        on_connection_failed()
    raise RpcError(
        "CONNECTION_FAILED",
        f"Cannot connect to {url} after {retries} attempts",
        suggestion="Check if the server is running.",
        data=str(last_err) if last_err else None,
    )
