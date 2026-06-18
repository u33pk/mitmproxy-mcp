"""Helpers for interacting with mitmproxy internals."""

from __future__ import annotations

import base64
import logging
from collections.abc import Sequence
from typing import Any

from mitmproxy import http
from mitmproxy.connection import Client, Server

logger = logging.getLogger(__name__)


def _normalize_headers(headers: dict[str, str] | list[dict[str, str]] | None) -> dict[str, str]:
    """Normalize headers input into a dict."""
    if headers is None:
        return {}
    if isinstance(headers, dict):
        return headers
    result: dict[str, str] = {}
    for item in headers:
        if isinstance(item, dict) and "name" in item and "value" in item:
            result[item["name"]] = item["value"]
    return result


def create_http_flow(
    method: str,
    url: str,
    headers: dict[str, str] | list[dict[str, str]] | None = None,
    body: str | bytes | None = None,
) -> http.HTTPFlow:
    """Create a minimal HTTPFlow suitable for replay.client."""
    normalized_headers = _normalize_headers(headers)
    request = http.Request.make(method, url, content=body or b"", headers=normalized_headers)

    client = Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0))
    server = Server(address=(request.host, request.port))

    flow = http.HTTPFlow(client, server)
    flow.request = request
    return flow


def replay_flows(
    call: Any,
    flows: Sequence[http.HTTPFlow],
    use_modified: bool = False,
) -> dict[str, Any]:
    """Replay a list of flows using mitmproxy's built-in replay.client command.

    `call` is a callable that invokes a mitmproxy command, e.g. proxy_manager.call.
    """
    try:
        prepared: list[http.HTTPFlow] = []
        for flow in flows:
            if not use_modified:
                flow.revert()
            prepared.append(flow)

        call("replay.client", prepared)
        return {
            "success": True,
            "queued": len(prepared),
        }
    except Exception as e:
        logger.exception("Failed to replay flows")
        return {"success": False, "error": str(e)}


def save_flows(
    call: Any,
    flows: Sequence[http.HTTPFlow],
    path: str,
) -> dict[str, Any]:
    """Save flows to a .mitm file using mitmproxy's built-in save.file command.

    `call` is a callable that invokes a mitmproxy command, e.g. proxy_manager.call.
    """
    try:
        call("save.file", list(flows), path)
        return {"success": True, "saved": len(flows), "path": path}
    except Exception as e:
        logger.exception("Failed to save flows")
        return {"success": False, "error": str(e)}


def decode_body(content: str | None, encoding: str = "text") -> bytes | None:
    """Decode a body string (text or base64) back to bytes."""
    if content is None:
        return None
    if encoding == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8")
