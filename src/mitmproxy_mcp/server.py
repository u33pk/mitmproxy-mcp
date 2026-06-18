"""FastMCP server exposing mitmproxy capture/replay/modify tools."""

from __future__ import annotations

import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from mitmproxy import http

from mitmproxy_mcp.models import (
    Header,
    ResponseModel,
    flow_to_model,
    update_request_from_model,
    update_response_from_model,
)
from mitmproxy_mcp.proxy import ProxyManager
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.utils import create_http_flow, decode_body, replay_flows, save_flows

# Ensure all logging goes to stderr so stdout remains clean for MCP stdio.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

mcp = FastMCP("mitmproxy-mcp")
store = FlowStore()
proxy_manager = ProxyManager(store)


def _get_flow_or_raise(flow_id: int) -> http.HTTPFlow:
    flow = store.get(flow_id)
    if flow is None:
        raise ValueError(f"Flow with id {flow_id} not found")
    return flow


# ---------------------------------------------------------------------------
# Proxy control tools
# ---------------------------------------------------------------------------

@mcp.tool()
def proxy_start(
    host: str = "127.0.0.1",
    port: int = 8080,
    capture_filter: str | None = None,
    ssl_insecure: bool = False,
    upstream_proxy: str | None = None,
) -> dict[str, Any]:
    """Start the mitmproxy capture proxy."""
    return proxy_manager.start(
        host=host,
        port=port,
        capture_filter=capture_filter,
        ssl_insecure=ssl_insecure,
        upstream_proxy=upstream_proxy,
    )


@mcp.tool()
def proxy_stop() -> dict[str, Any]:
    """Stop the mitmproxy capture proxy."""
    return proxy_manager.stop()


@mcp.tool()
def proxy_status() -> dict[str, Any]:
    """Get the current proxy status and number of captured flows."""
    return proxy_manager.status()


# ---------------------------------------------------------------------------
# Flow file tools
# ---------------------------------------------------------------------------

@mcp.tool()
def flows_load(path: str) -> dict[str, Any]:
    """Load flows from a .mitm file into memory."""
    try:
        count = store.load(path)
        return {"success": True, "loaded": count, "path": path}
    except Exception as e:
        logger.exception("Failed to load flows")
        return {"success": False, "error": str(e)}


@mcp.tool()
def flows_save(path: str) -> dict[str, Any]:
    """Save all in-memory flows to a .mitm file."""
    if proxy_manager.is_running:
        try:
            flows = list(store.snapshot().values())
            return save_flows(proxy_manager.call, flows, path)
        except RuntimeError:
            pass
    # Fallback when proxy is not running.
    try:
        count = store.save(path)
        return {"success": True, "saved": count, "path": path}
    except Exception as e:
        logger.exception("Failed to save flows")
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Flow viewing tools
# ---------------------------------------------------------------------------

@mcp.tool()
def flows_list(
    offset: int = 0,
    limit: int = 50,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """List captured flows with optional filtering and pagination."""
    items = store.list(
        offset=offset,
        limit=limit,
        host=host,
        method=method,
        status=status,
        search=search,
    )
    return {
        "total": store.count(),
        "offset": offset,
        "limit": limit,
        "flows": [flow_to_model(f).model_dump() for _, f in items],
    }


@mcp.tool()
def flow_get(flow_id: int) -> dict[str, Any]:
    """Get the full details of a single flow."""
    try:
        flow = _get_flow_or_raise(flow_id)
        return {"success": True, "flow": flow_to_model(flow).model_dump()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flows_clear(stop_proxy: bool = False) -> dict[str, Any]:
    """Clear all in-memory flows. Optionally stop the proxy too."""
    count = store.clear()
    result: dict[str, Any] = {"success": True, "cleared": count}
    if stop_proxy:
        result["proxy_stopped"] = proxy_manager.stop()
    return result


# ---------------------------------------------------------------------------
# Replay tools
# ---------------------------------------------------------------------------

@mcp.tool()
def flow_replay(flow_id: int, use_modified: bool = True) -> dict[str, Any]:
    """Replay a captured flow using mitmproxy's built-in replay.client."""
    try:
        flow = _get_flow_or_raise(flow_id)
        if not proxy_manager.is_running:
            return {
                "success": False,
                "error": "Proxy is not running. Start it with proxy_start before replaying.",
            }
        return replay_flows(proxy_manager.call, [flow], use_modified=use_modified)
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def request_send(
    method: str,
    url: str,
    headers: list[Header] | None = None,
    body: str | None = None,
    body_encoding: str = "text",
) -> dict[str, Any]:
    """Send a new HTTP request using mitmproxy's built-in replay.client."""
    try:
        if not proxy_manager.is_running:
            return {
                "success": False,
                "error": "Proxy is not running. Start it with proxy_start before sending requests.",
            }

        headers_dict = {h.name: h.value for h in headers} if headers else {}
        raw_body = decode_body(body, body_encoding)
        flow = create_http_flow(method, url, headers_dict, raw_body)
        store.add(flow)
        return replay_flows(proxy_manager.call, [flow], use_modified=True)
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Modification tools
# ---------------------------------------------------------------------------

@mcp.tool()
def flow_update(
    flow_id: int,
    request_method: str | None = None,
    request_path: str | None = None,
    request_headers: list[Header] | None = None,
    request_body: str | None = None,
    request_body_encoding: str = "text",
    response_status: int | None = None,
    response_reason: str | None = None,
    response_headers: list[Header] | None = None,
    response_body: str | None = None,
    response_body_encoding: str = "text",
    comment: str | None = None,
    marked: bool | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Modify a captured request/response and its metadata."""
    try:
        flow = _get_flow_or_raise(flow_id)

        if any(
            [
                request_method,
                request_path,
                request_headers,
                request_body is not None,
            ]
        ):
            request_model = flow_to_model(flow).request
            if request_method:
                request_model.method = request_method
            if request_path:
                request_model.path = request_path
            if request_headers:
                request_model.headers = request_headers
            if request_body is not None:
                request_model.content = request_body
                request_model.content_encoding = request_body_encoding  # type: ignore[assignment]
            update_request_from_model(flow.request, request_model)

        if any(
            [
                response_status,
                response_reason,
                response_headers,
                response_body is not None,
            ]
        ):
            if flow.response is None:
                flow.response = http.Response.make(
                    status_code=response_status or 200,
                    content=b"",
                )
            flow_model = flow_to_model(flow)
            response_model = flow_model.response
            if response_model is None:
                response_model = ResponseModel(
                    http_version="HTTP/1.1",
                    status_code=response_status or 200,
                    reason=response_reason or "",
                    headers=response_headers or [],
                    content=response_body,
                    content_encoding=response_body_encoding,  # type: ignore[arg-type]
                    content_length=0,
                    timestamp_start=0,
                    timestamp_end=0,
                )
            else:
                if response_status:
                    response_model.status_code = response_status
                if response_reason:
                    response_model.reason = response_reason
                if response_headers:
                    response_model.headers = response_headers
                if response_body is not None:
                    response_model.content = response_body
                    response_model.content_encoding = response_body_encoding  # type: ignore[assignment]
            update_response_from_model(flow.response, response_model)

        store.update(flow_id, comment=comment, marked=marked, tags=tags)
        return {"success": True, "flow": flow_to_model(flow).model_dump()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flow_create(
    method: str,
    url: str,
    headers: list[Header] | None = None,
    body: str | None = None,
    body_encoding: str = "text",
    comment: str | None = None,
) -> dict[str, Any]:
    """Create a new request flow and store it (without sending)."""
    try:
        headers_dict = {h.name: h.value for h in headers} if headers else {}
        raw_body = decode_body(body, body_encoding)
        flow = create_http_flow(method, url, headers_dict, raw_body)
        if comment:
            flow.comment = comment
        store_id = store.add(flow)
        return {
            "success": True,
            "flow_id": store_id,
            "flow": flow_to_model(flow).model_dump(),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flow_delete(flow_id: int) -> dict[str, Any]:
    """Delete a flow from memory."""
    if store.delete(flow_id):
        return {"success": True}
    return {"success": False, "error": f"Flow with id {flow_id} not found"}


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
