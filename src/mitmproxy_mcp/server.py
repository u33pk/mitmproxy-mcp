"""FastMCP server exposing mitmproxy capture/replay/modify tools."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from mitmproxy import http
from mitmproxy import options as mitmproxy_options

from mitmproxy_mcp.json_tools import extract_with_jsonpath, maybe_preview_content
from mitmproxy_mcp.models import (
    Header,
    ResponseModel,
    flow_to_model,
    update_request_from_model,
    update_response_from_model,
)
from mitmproxy_mcp.proxy import CaptureRule, ProxyManager
from mitmproxy_mcp.rules import Rule
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
    extra_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start the mitmproxy capture proxy.

    extra_options can be used to pass any mitmproxy-native option to
    options.Options, for example {"mode": ["socks5"]} or
    {"tcp_hosts": ["example.com"]}. Use proxy_list_options to discover
    available keys and their defaults.
    """
    return proxy_manager.start(
        host=host,
        port=port,
        capture_filter=capture_filter,
        ssl_insecure=ssl_insecure,
        upstream_proxy=upstream_proxy,
        extra_options=extra_options,
    )


@mcp.tool()
def proxy_stop() -> dict[str, Any]:
    """Stop the mitmproxy capture proxy."""
    return proxy_manager.stop()


@mcp.tool()
def proxy_status() -> dict[str, Any]:
    """Get the current proxy status and number of captured flows."""
    return proxy_manager.status()


@mcp.tool()
def proxy_list_options() -> dict[str, Any]:
    """List available mitmproxy options that can be passed via extra_options."""
    opts = mitmproxy_options.Options()
    result: dict[str, Any] = {}
    for name, opt in opts._options.items():
        result[name] = {
            "default": opt.default,
            "type": str(opt.typespec),
            "help": opt.help,
        }
    return {"options": result}


# ---------------------------------------------------------------------------
# Automatic rule tools
# ---------------------------------------------------------------------------


@mcp.tool()
def rules_list() -> dict[str, Any]:
    """List all configured automatic rules."""
    try:
        rules = proxy_manager.list_rules()
        return {"success": True, "rules": [r.model_dump(exclude_none=True) for r in rules]}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def rule_add(rule: Rule) -> dict[str, Any]:
    """Add or replace an automatic rule.

    Rules match live HTTP flows by a mitmproxy flowfilter expression and apply
    a list of actions automatically. Use rules_list to see examples after
    adding a rule.
    """
    try:
        proxy_manager.add_rule(rule)
        return {"success": True, "rule": rule.model_dump(exclude_none=True)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def rule_update(rule_id: str, rule: Rule) -> dict[str, Any]:
    """Replace an existing automatic rule by id."""
    try:
        if rule_id != rule.id:
            # If the id changed, delete the old one and add the new one.
            proxy_manager.delete_rule(rule_id)
            proxy_manager.add_rule(rule)
            return {"success": True, "rule": rule.model_dump(exclude_none=True)}
        updated = proxy_manager.update_rule(rule_id, rule.model_dump(exclude_none=True))
        if updated is None:
            return {"success": False, "error": f"Rule with id {rule_id} not found"}
        return {"success": True, "rule": updated.model_dump(exclude_none=True)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def rule_delete(rule_id: str) -> dict[str, Any]:
    """Delete an automatic rule by id."""
    if proxy_manager.delete_rule(rule_id):
        return {"success": True}
    return {"success": False, "error": f"Rule with id {rule_id} not found"}


@mcp.tool()
def rules_clear() -> dict[str, Any]:
    """Delete all automatic rules."""
    count = proxy_manager.clear_rules()
    return {"success": True, "cleared": count}


# ---------------------------------------------------------------------------
# Capture rule tools
# ---------------------------------------------------------------------------


@mcp.tool()
def capture_rules_list() -> dict[str, Any]:
    """List all configured capture rules."""
    try:
        rules = proxy_manager.list_capture_rules()
        return {"success": True, "rules": [r.model_dump(exclude_none=True) for r in rules]}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def capture_rule_add(rule: CaptureRule) -> dict[str, Any]:
    """Add or replace a capture rule.

    Capture rules decide which live HTTP flows are stored. An `include` rule
    means "only capture if this matches" (when any include rule exists). An
    `exclude` rule means "never capture if this matches". Exclude rules are
    evaluated before include rules.
    """
    try:
        proxy_manager.add_capture_rule(rule)
        return {"success": True, "rule": rule.model_dump(exclude_none=True)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def capture_rule_update(rule_id: str, rule: CaptureRule) -> dict[str, Any]:
    """Replace an existing capture rule by id."""
    try:
        if rule_id != rule.id:
            proxy_manager.delete_capture_rule(rule_id)
            proxy_manager.add_capture_rule(rule)
            return {"success": True, "rule": rule.model_dump(exclude_none=True)}
        updated = proxy_manager.update_capture_rule(
            rule_id, rule.model_dump(exclude_none=True)
        )
        if updated is None:
            return {
                "success": False,
                "error": f"Capture rule with id {rule_id} not found",
            }
        return {"success": True, "rule": updated.model_dump(exclude_none=True)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def capture_rule_delete(rule_id: str) -> dict[str, Any]:
    """Delete a capture rule by id."""
    if proxy_manager.delete_capture_rule(rule_id):
        return {"success": True}
    return {
        "success": False,
        "error": f"Capture rule with id {rule_id} not found",
    }


@mcp.tool()
def capture_rules_clear() -> dict[str, Any]:
    """Delete all capture rules."""
    count = proxy_manager.clear_capture_rules()
    return {"success": True, "cleared": count}


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
def flow_get(
    flow_id: int,
    include_content: bool = True,
    max_content_size: int | None = None,
) -> dict[str, Any]:
    """Get the full details of a single flow.

    If max_content_size is set and content exceeds it, JSON bodies are
    replaced with a structure preview and other text bodies are truncated.
    """
    try:
        flow = _get_flow_or_raise(flow_id)
        flow_data = flow_to_model(flow).model_dump()

        if not include_content:
            flow_data["request"]["content"] = None
            if flow_data.get("response"):
                flow_data["response"]["content"] = None
            return {"success": True, "flow": flow_data}

        if max_content_size is not None:
            request = flow_data["request"]
            request.update(
                maybe_preview_content(
                    request.get("content"),
                    request.get("content_encoding", "text"),
                    max_content_size,
                )
            )
            response = flow_data.get("response")
            if response:
                response.update(
                    maybe_preview_content(
                        response.get("content"),
                        response.get("content_encoding", "text"),
                        max_content_size,
                    )
                )

        return {"success": True, "flow": flow_data}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flow_extract_json(
    flow_id: int,
    content_type: str,
    json_paths: list[str],
) -> dict[str, Any]:
    """Extract specific fields from JSON request/response content using JSONPath."""
    try:
        flow = _get_flow_or_raise(flow_id)

        if content_type == "request":
            raw_content = flow.request.raw_content
            headers = dict(flow.request.headers)
        elif content_type == "response":
            if flow.response is None:
                return {
                    "success": False,
                    "error": f"Flow {flow_id} has no response",
                }
            raw_content = flow.response.raw_content
            headers = dict(flow.response.headers)
        else:
            return {
                "success": False,
                "error": "content_type must be 'request' or 'response'",
            }

        if raw_content is None:
            return {
                "success": False,
                "error": f"No {content_type} content available",
            }

        content_type_header = headers.get("Content-Type", "").lower()
        if "application/json" not in content_type_header and "text/json" not in content_type_header:
            # Still attempt to parse; many responses omit the proper header.
            pass

        try:
            text = raw_content.decode("utf-8")
        except UnicodeDecodeError as e:
            return {
                "success": False,
                "error": f"{content_type} content is not valid UTF-8: {e}",
            }

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"{content_type} content is not valid JSON: {e}",
            }

        result = extract_with_jsonpath(data, json_paths)
        return {"success": True, "extracted": result}
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


@mcp.tool()
def clear_all(stop_proxy: bool = False) -> dict[str, Any]:
    """Clear all in-memory flows, automatic rules and capture rules.

    Optionally stop the proxy too.
    """
    try:
        return proxy_manager.clear_all(stop_proxy=stop_proxy)
    except Exception as e:
        return {"success": False, "error": str(e)}


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
def flow_resume(flow_id: int) -> dict[str, Any]:
    """Resume an intercepted (breakpoint-paused) flow."""
    try:
        flow = _get_flow_or_raise(flow_id)
        if not proxy_manager.is_running:
            return {
                "success": False,
                "error": "Proxy is not running. Start it with proxy_start before resuming.",
            }
        proxy_manager.call("flow.resume", [flow])
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flow_kill(flow_id: int) -> dict[str, Any]:
    """Kill a running or intercepted flow."""
    try:
        flow = _get_flow_or_raise(flow_id)
        if not proxy_manager.is_running:
            return {
                "success": False,
                "error": "Proxy is not running. Start it with proxy_start before killing.",
            }
        proxy_manager.call("flow.kill", [flow])
        return {"success": True}
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
