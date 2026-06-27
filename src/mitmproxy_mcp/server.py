"""FastMCP server exposing mitmproxy capture/replay/modify tools."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mitmproxy import http
from mitmproxy import options as mitmproxy_options

from mitmproxy_mcp.crypto import MODIFIED_REQUEST_KEY, MODIFIED_RESPONSE_KEY
from mitmproxy_mcp.json_tools import extract_with_jsonpath, maybe_preview_content
from mitmproxy_mcp.mappings import MapLocalRule, MapRemoteRule
from mitmproxy_mcp.models import (
    Header,
    ResponseModel,
    flow_to_model,
    update_request_from_model,
    update_response_from_model,
)
from mitmproxy_mcp.proxy import CaptureRule, ProxyManager
from mitmproxy_mcp.resources import (
    CA_STATUS_URI,
    CONFIG_RULES_URI,
    CRYPTO_SCRIPTS_URI,
    EVENTS_LATEST_URI,
    FLOW_DETAIL_TEMPLATE,
    FLOWS_LATEST_URI,
    PROXY_STATUS_URI,
    ca_status_resource,
    config_rules_resource,
    crypto_scripts_resource,
    events_latest_resource,
    flow_detail_resource,
    flows_latest_resource,
    proxy_status_resource,
)
from mitmproxy_mcp.rules import Rule
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.tool_info import get_tool_info
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
proxy_manager = ProxyManager(store, source_proxy="main")
aux_proxy_manager = ProxyManager(store, source_proxy="aux")


# =============================================================================
# MCP resources
# =============================================================================


@mcp.resource(PROXY_STATUS_URI, name="Proxy Status", mime_type="application/json")
def proxy_status() -> dict[str, Any]:
    """Current proxy status: running state, listen address, capture counts, CA summary."""
    return proxy_status_resource(proxy_manager)


@mcp.resource(FLOWS_LATEST_URI, name="Latest Flows", mime_type="application/json")
def flows_latest() -> list[dict[str, Any]]:
    """Lightweight list of the most recent captured flows (index fields only)."""
    return flows_latest_resource(store)


@mcp.resource(CONFIG_RULES_URI, name="Active Rules", mime_type="application/json")
def config_rules() -> dict[str, Any]:
    """Snapshot of all active rules and loaded crypto scripts."""
    return config_rules_resource(proxy_manager)


@mcp.resource(EVENTS_LATEST_URI, name="Latest Events", mime_type="application/json")
def events_latest() -> list[dict[str, Any]]:
    """Recent internal events (proxy lifecycle, captured flows, rule matches, crypto errors)."""
    main_events = events_latest_resource(proxy_manager.event_buffer, limit=10)
    aux_events = events_latest_resource(aux_proxy_manager.event_buffer, limit=10)
    combined = sorted(main_events + aux_events, key=lambda e: e.get("timestamp", 0), reverse=True)
    return combined[:10]


@mcp.resource(CRYPTO_SCRIPTS_URI, name="Crypto Scripts", mime_type="application/json")
def crypto_scripts() -> list[dict[str, Any]]:
    """Loaded encryption/decryption scripts and their runtime error state."""
    return crypto_scripts_resource(proxy_manager)


@mcp.resource(CA_STATUS_URI, name="CA Status", mime_type="application/json")
def ca_status() -> dict[str, Any]:
    """Current certificate authority and client certificate configuration."""
    return ca_status_resource(proxy_manager)


# Register the flow-detail template resource.
mcp._resource_manager.add_template(
    lambda flow_id: flow_detail_resource(store, int(flow_id)),
    uri_template=FLOW_DETAIL_TEMPLATE,
    name="Flow Detail",
    mime_type="application/json",
    description="Full details of a single captured flow.",
)


# =============================================================================
# Internal helpers (not exposed as MCP tools)
# =============================================================================


def _get_proxy_by_id(proxy_id: str) -> ProxyManager:
    """Return the proxy manager for the given id ('main' or 'aux')."""
    if proxy_id == "aux":
        return aux_proxy_manager
    return proxy_manager


def _get_source_proxy_for_flow(flow: http.HTTPFlow) -> str:
    """Return the proxy id that captured the given flow (defaults to 'main')."""
    if flow.metadata:
        return flow.metadata.get("mitmproxy_mcp_source_proxy", "main")
    return "main"


def _get_flow_or_raise(flow_id: int) -> http.HTTPFlow:
    flow = store.get(flow_id)
    if flow is None:
        raise ValueError(f"Flow with id {flow_id} not found")
    return flow


def _get_flows_by_ids(flow_ids: list[int]) -> list[http.HTTPFlow]:
    flows: list[http.HTTPFlow] = []
    for fid in flow_ids:
        flow = store.get(fid)
        if flow is None:
            raise ValueError(f"Flow with id {fid} not found")
        flows.append(flow)
    return flows


def _proxy_start(
    target_proxy: ProxyManager | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    capture_filter: str | None = None,
    ssl_insecure: bool = False,
    upstream_proxy: str | None = None,
    extra_options: dict[str, Any] | None = None,
    webui: bool = False,
    web_port: int = 8081,
) -> dict[str, Any]:
    target = target_proxy or proxy_manager
    return target.start(
        host=host,
        port=port,
        capture_filter=capture_filter,
        ssl_insecure=ssl_insecure,
        upstream_proxy=upstream_proxy,
        extra_options=extra_options,
        webui=webui,
        web_port=web_port,
    )


def _proxy_list_options() -> dict[str, Any]:
    opts = mitmproxy_options.Options()
    result: dict[str, Any] = {}
    for name, opt in opts._options.items():
        result[name] = {
            "default": opt.default,
            "type": str(opt.typespec),
            "help": opt.help,
        }
    return {"options": result}


def _http_flows_list(
    offset: int = 0,
    limit: int = 50,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    items = store.list(
        offset=offset,
        limit=limit,
        host=host,
        method=method,
        status=status,
        search=search,
    )
    # WebSocket flows are owned by websocket_ctl.
    http_items = [(sid, f) for sid, f in items if f.websocket is None]
    return {
        "total": len(http_items),
        "offset": offset,
        "limit": limit,
        "flows": [flow_to_model(f, store_id=i).model_dump() for i, f in http_items],
    }


def _flow_get(
    flow_id: int,
    include_content: bool = True,
    max_content_size: int | None = None,
    allow_websocket: bool = True,
) -> dict[str, Any]:
    flow = _get_flow_or_raise(flow_id)
    if not allow_websocket and flow.websocket is not None:
        return {"success": False, "error": f"Flow {flow_id} is a WebSocket flow; use websocket_ctl"}
    flow_data = flow_to_model(flow, store_id=flow_id, max_content_size=max_content_size).model_dump()

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


def _flow_extract_json(
    flow_id: int,
    target: Literal["request", "response"],
    json_paths: list[str],
) -> dict[str, Any]:
    flow = _get_flow_or_raise(flow_id)

    if target == "request":
        raw_content = flow.request.raw_content
        headers = dict(flow.request.headers)
    elif target == "response":
        if flow.response is None:
            return {"success": False, "error": f"Flow {flow_id} has no response"}
        raw_content = flow.response.raw_content
        headers = dict(flow.response.headers)
    else:
        return {"success": False, "error": "target must be 'request' or 'response'"}

    if raw_content is None:
        return {"success": False, "error": f"No {target} content available"}

    content_type_header = headers.get("Content-Type", "").lower()
    if "application/json" not in content_type_header and "text/json" not in content_type_header:
        pass

    try:
        text = raw_content.decode("utf-8")
    except UnicodeDecodeError as e:
        return {"success": False, "error": f"{target} content is not valid UTF-8: {e}"}

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"{target} content is not valid JSON: {e}"}

    result = extract_with_jsonpath(data, json_paths)
    return {"success": True, "extracted": result}


def _flow_update(
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
    decrypted_request_body: str | None = None,
    decrypted_response_body: str | None = None,
    decrypted_body_encoding: str = "text",
    comment: str | None = None,
    marked: bool | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
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

    # Decrypted plaintext edits are stored as metadata; the CryptoAddon will
    # re-encrypt them on the next outgoing request/response or replay.
    if flow.metadata is None:
        flow.metadata = {}
    if decrypted_request_body is not None:
        flow.metadata[MODIFIED_REQUEST_KEY] = decode_body(decrypted_request_body, decrypted_body_encoding)
    if decrypted_response_body is not None:
        flow.metadata[MODIFIED_RESPONSE_KEY] = decode_body(decrypted_response_body, decrypted_body_encoding)

    store.update(flow_id, comment=comment, marked=marked, tags=tags)
    return {"success": True, "flow": flow_to_model(flow, store_id=flow_id).model_dump()}


def _flow_create(
    method: str,
    url: str,
    headers: list[Header] | None = None,
    body: str | None = None,
    body_encoding: str = "text",
    comment: str | None = None,
) -> dict[str, Any]:
    headers_dict = {h.name: h.value for h in headers} if headers else {}
    raw_body = decode_body(body, body_encoding)
    flow = create_http_flow(method, url, headers_dict, raw_body)
    if comment:
        flow.comment = comment
    store_id = store.add(flow)
    return {
        "success": True,
        "flow_id": store_id,
        "flow": flow_to_model(flow, store_id=store_id).model_dump(),
    }


def _request_send(
    method: str,
    url: str,
    headers: list[Header] | None = None,
    body: str | None = None,
    body_encoding: str = "text",
) -> dict[str, Any]:
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


def _flow_replay(flow_id: int, use_modified: bool = True) -> dict[str, Any]:
    flow = _get_flow_or_raise(flow_id)
    source = _get_source_proxy_for_flow(flow)
    target = _get_proxy_by_id(source)
    if not target.is_running:
        return {
            "success": False,
            "error": f"Proxy '{source}' is not running. Start it before replaying.",
        }
    return replay_flows(target.call, [flow], use_modified=use_modified)


def _flow_resume(flow_id: int) -> dict[str, Any]:
    flow = _get_flow_or_raise(flow_id)
    source = _get_source_proxy_for_flow(flow)
    target = _get_proxy_by_id(source)
    if not target.is_running:
        return {
            "success": False,
            "error": f"Proxy '{source}' is not running. Start it before resuming.",
        }
    target.call("flow.resume", [flow])
    return {"success": True}


def _flow_kill(flow_id: int) -> dict[str, Any]:
    flow = _get_flow_or_raise(flow_id)
    source = _get_source_proxy_for_flow(flow)
    target = _get_proxy_by_id(source)
    if not target.is_running:
        return {
            "success": False,
            "error": f"Proxy '{source}' is not running. Start it before killing.",
        }
    target.call("flow.kill", [flow])
    return {"success": True}


def _flows_save(path: str) -> dict[str, Any]:
    if proxy_manager.is_running:
        try:
            flows = list(store.snapshot().values())
            return save_flows(proxy_manager.call, flows, path)
        except RuntimeError:
            pass
    try:
        count = store.save(path)
        return {"success": True, "saved": count, "path": path}
    except Exception as e:
        logger.exception("Failed to save flows")
        return {"success": False, "error": str(e)}


def _mock_server_start(
    flow_ids: list[int] | None = None,
    ignore_host: bool = False,
    ignore_port: bool = False,
    ignore_params: list[str] | None = None,
    ignore_content: bool = False,
    extra: str = "forward",
) -> dict[str, Any]:
    if not proxy_manager.is_running:
        return {
            "success": False,
            "error": "Proxy is not running. Start it with proxy_start before using mock server.",
        }
    flows: list[http.HTTPFlow] = (
        _get_flows_by_ids(flow_ids) if flow_ids else store.list_flows()
    )
    if not flows:
        return {"success": False, "error": "No flows available to mock"}

    proxy_manager.call("replay.server.stop")
    proxy_manager.call(
        "set", "server_replay_ignore_host", "true" if ignore_host else "false"
    )
    proxy_manager.call(
        "set", "server_replay_ignore_port", "true" if ignore_port else "false"
    )
    proxy_manager.call(
        "set",
        "server_replay_ignore_params",
        "[" + ",".join(ignore_params or []) + "]",
    )
    proxy_manager.call(
        "set",
        "server_replay_ignore_content",
        "true" if ignore_content else "false",
    )
    proxy_manager.call("set", "server_replay_extra", extra)

    proxy_manager.call("replay.server", flows)
    count = proxy_manager.call("replay.server.count")
    return {"success": True, "mocked_flows": count}


def _mock_server_add_flows(flow_ids: list[int]) -> dict[str, Any]:
    if not proxy_manager.is_running:
        return {
            "success": False,
            "error": "Proxy is not running. Start it with proxy_start before using mock server.",
        }
    flows = _get_flows_by_ids(flow_ids)
    proxy_manager.call("replay.server.add", flows)
    count = proxy_manager.call("replay.server.count")
    return {"success": True, "mocked_flows": count}


# =============================================================================
# Composite MCP tools
# =============================================================================


@mcp.tool()
def proxy_ctl(
    cmd: Literal[
        "start", "stop", "status", "list_options", "clear_all", "wireguard_config"
    ],
    proxy_id: Literal["main", "aux"] = "main",
    host: str = "127.0.0.1",
    port: int = 8080,
    capture_filter: str | None = None,
    ssl_insecure: bool = False,
    upstream_proxy: str | None = None,
    extra_options: dict[str, Any] | None = None,
    stop_proxy: bool = False,
    webui: bool = False,
    web_port: int = 8081,
) -> dict[str, Any]:
    """Control the proxy. Commands: start, stop, status, list_options, clear_all, wireguard_config. Use tool_info('proxy_ctl') for details."""
    try:
        if cmd == "start":
            target = _get_proxy_by_id(proxy_id)
            return _proxy_start(
                target_proxy=target,
                host=host,
                port=port,
                capture_filter=capture_filter,
                ssl_insecure=ssl_insecure,
                upstream_proxy=upstream_proxy,
                extra_options=extra_options,
                webui=webui,
                web_port=web_port,
            )
        if cmd == "stop":
            target = _get_proxy_by_id(proxy_id)
            return target.stop()
        if cmd == "status":
            result = proxy_manager.status()
            if aux_proxy_manager.is_running:
                result["aux_proxy"] = aux_proxy_manager.status()
            return result
        if cmd == "wireguard_config":
            target = _get_proxy_by_id(proxy_id)
            return target.wireguard_config()
        if cmd == "list_options":
            return _proxy_list_options()
        if cmd == "clear_all":
            target = _get_proxy_by_id(proxy_id)
            return target.clear_all(stop_proxy=stop_proxy)
        return {"success": False, "error": f"Unknown proxy command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def ca_ctl(
    cmd: Literal[
        "status",
        "export_ca",
        "set_verify_upstream",
        "set_upstream_ca",
        "clear_upstream_ca",
        "set_client_cert",
        "clear_client_cert",
    ],
    enabled: bool = True,
    ca_path: str | None = None,
    cert_path: str | None = None,
    key_path: str | None = None,
    passphrase: str | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Manage certificates and CA settings. Commands: status, export_ca, set_verify_upstream, set_upstream_ca, clear_upstream_ca, set_client_cert, clear_client_cert. Use tool_info('ca_ctl') for details."""
    try:
        if cmd == "status":
            return proxy_manager.ca_status()
        if cmd == "export_ca":
            return proxy_manager.export_ca(output_dir)
        if cmd == "set_verify_upstream":
            return proxy_manager.set_verify_upstream(enabled)
        if cmd == "set_upstream_ca":
            if ca_path is None:
                return {"success": False, "error": "ca_path is required"}
            return proxy_manager.set_upstream_ca(ca_path)
        if cmd == "clear_upstream_ca":
            return proxy_manager.clear_upstream_ca()
        if cmd == "set_client_cert":
            if cert_path is None:
                return {"success": False, "error": "cert_path is required"}
            return proxy_manager.set_client_cert(cert_path, key_path, passphrase)
        if cmd == "clear_client_cert":
            return proxy_manager.clear_client_cert()
        return {"success": False, "error": f"Unknown ca command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _websocket_get(flow_id: int, include_content: bool, max_content_size: int | None) -> dict[str, Any]:
    flow = store.get(flow_id)
    if flow is None:
        return {"success": False, "error": f"Flow with id {flow_id} not found"}
    if flow.websocket is None:
        return {"success": False, "error": f"Flow with id {flow_id} is not a WebSocket connection"}
    return {
        "success": True,
        "flow": flow_to_model(flow, store_id=flow_id, max_content_size=max_content_size).model_dump(),
    }


@mcp.tool()
def crypt_ctl(
    cmd: Literal["list", "load", "unload", "reload", "status"],
    proxy_id: Literal["main", "aux"] = "main",
    script_path: str | None = None,
    script_id: str | None = None,
) -> dict[str, Any]:
    """Load and manage user-written encryption/decryption scripts. Commands: list, load, unload, reload, status. Use tool_info('crypt_ctl') for details."""
    try:
        target = _get_proxy_by_id(proxy_id)
        if cmd == "list":
            return {"success": True, "scripts": target.list_crypto_scripts()}
        if cmd == "load":
            if script_path is None:
                return {"success": False, "error": "script_path is required"}
            return target.load_crypto_script(script_path)
        if cmd == "unload":
            if script_id is None:
                return {"success": False, "error": "script_id is required"}
            return target.unload_crypto_script(script_id)
        if cmd == "reload":
            if script_id is None:
                return {"success": False, "error": "script_id is required"}
            return target.reload_crypto_script(script_id)
        if cmd == "status":
            if script_id is None:
                return {"success": False, "error": "script_id is required"}
            status = target.get_crypto_script_status(script_id)
            if status is None:
                return {"success": False, "error": f"Crypto script '{script_id}' not found"}
            return {"success": True, "script": status}
        return {"success": False, "error": f"Unknown crypt command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def websocket_ctl(
    cmd: Literal[
        "list", "get", "inject", "connect",
        "list_rules", "add_rule", "delete_rule", "clear_rules",
    ],
    proxy_id: Literal["main", "aux"] = "main",
    flow_id: int | None = None,
    to_client: bool = True,
    message: str = "",
    binary: bool = False,
    url: str | None = None,
    headers: list[Header] | None = None,
    subprotocols: list[str] | None = None,
    messages: list[str] | None = None,
    wait_for: int = 0,
    timeout: float = 10,
    rule: dict[str, Any] | None = None,
    rule_id: str | None = None,
    offset: int = 0,
    limit: int = 50,
    include_content: bool = True,
    max_content_size: int | None = None,
) -> dict[str, Any]:
    """Manage WebSocket connections: list, get, inject, connect, and message modification rules. Use tool_info('websocket_ctl') for details."""
    try:
        if cmd == "list":
            items = store.list(offset=offset, limit=limit, websocket_only=True)
            return {
                "success": True,
                "total": store.count(websocket_only=True),
                "offset": offset,
                "limit": limit,
                "flows": [flow_to_model(f, store_id=i).model_dump() for i, f in items],
            }
        if cmd == "get":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            return _websocket_get(flow_id, include_content, max_content_size)
        if cmd == "inject":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            flow = store.get(flow_id)
            if flow is None:
                return {"success": False, "error": f"Flow with id {flow_id} not found"}
            source = _get_source_proxy_for_flow(flow)
            target = _get_proxy_by_id(source)
            return target.inject_websocket(flow_id, to_client, message, binary)
        if cmd == "connect":
            if url is None:
                return {"success": False, "error": "url is required"}
            target = _get_proxy_by_id(proxy_id)
            header_dict = {h.name: h.value for h in headers} if headers else None
            return target.connect_websocket(
                url=url,
                headers=header_dict,
                subprotocols=subprotocols,
                messages=messages,
                wait_for=wait_for,
                timeout=timeout,
            )
        if cmd == "list_rules":
            target = _get_proxy_by_id(proxy_id)
            rules = target.list_websocket_rules()
            return {"success": True, "rules": [r.model_dump() for r in rules]}
        if cmd == "add_rule":
            if rule is None:
                return {"success": False, "error": "rule is required"}
            from mitmproxy_mcp.websocket_rules import WebSocketRule
            target = _get_proxy_by_id(proxy_id)
            ws_rule = WebSocketRule(**rule)
            target.add_websocket_rule(ws_rule)
            return {"success": True, "rule": ws_rule.model_dump()}
        if cmd == "delete_rule":
            if rule_id is None:
                return {"success": False, "error": "rule_id is required"}
            target = _get_proxy_by_id(proxy_id)
            deleted = target.delete_websocket_rule(rule_id)
            return {"success": deleted, "deleted": deleted}
        if cmd == "clear_rules":
            target = _get_proxy_by_id(proxy_id)
            count = target.clear_websocket_rules()
            return {"success": True, "cleared": count}
        return {"success": False, "error": f"Unknown websocket command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def http_ctl(
    cmd: Literal[
        "list", "get", "delete", "clear", "load", "save",
        "extract_json", "export_har", "import_har",
    ],
    flow_id: int | None = None,
    path: str | None = None,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    search: str | None = None,
    offset: int = 0,
    limit: int = 50,
    include_content: bool = True,
    max_content_size: int | None = None,
    jsonpath: list[str] | None = None,
    target: Literal["request", "response"] | None = None,
    stop_proxy: bool = False,
    flow_ids: list[int] | None = None,
) -> dict[str, Any]:
    """Manage captured HTTP flows. Commands: list, get, delete, clear, load, save, extract_json, export_har, import_har. Use tool_info('http_ctl') for details."""
    try:
        if cmd == "list":
            return _http_flows_list(
                offset=offset,
                limit=limit,
                host=host,
                method=method,
                status=status,
                search=search,
            )
        if cmd == "get":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            return _flow_get(
                flow_id=flow_id,
                include_content=include_content,
                max_content_size=max_content_size,
                allow_websocket=False,
            )
        if cmd == "delete":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            if store.delete(flow_id):
                return {"success": True}
            return {"success": False, "error": f"Flow with id {flow_id} not found"}
        if cmd == "clear":
            count = store.clear()
            result: dict[str, Any] = {"success": True, "cleared": count}
            if stop_proxy:
                result["proxy_stopped"] = proxy_manager.stop()
            return result
        if cmd == "load":
            if path is None:
                return {"success": False, "error": "path is required"}
            count = store.load(path)
            return {"success": True, "loaded": count, "path": path}
        if cmd == "save":
            if path is None:
                return {"success": False, "error": "path is required"}
            return _flows_save(path)
        if cmd == "export_har":
            if path is None:
                return {"success": False, "error": "path is required"}
            try:
                count = store.save_har(path, flow_ids=flow_ids)
                return {"success": True, "saved": count, "path": path}
            except Exception as e:
                logger.exception("Failed to export HAR")
                return {"success": False, "error": str(e)}
        if cmd == "import_har":
            if path is None:
                return {"success": False, "error": "path is required"}
            try:
                count = store.load_har(path)
                return {"success": True, "loaded": count, "path": path}
            except Exception as e:
                logger.exception("Failed to import HAR")
                return {"success": False, "error": str(e)}
        if cmd == "extract_json":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            if target is None:
                return {"success": False, "error": "target is required"}
            if not jsonpath:
                return {"success": False, "error": "jsonpath is required"}
            return _flow_extract_json(flow_id=flow_id, target=target, json_paths=jsonpath)
        return {"success": False, "error": f"Unknown http command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flow_action(
    action: Literal["replay", "resume", "kill", "update", "create", "send"],
    flow_id: int | None = None,
    method: str | None = None,
    url: str | None = None,
    headers: list[Header] | None = None,
    body: str | None = None,
    encoding: str = "text",
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
    decrypted_request_body: str | None = None,
    decrypted_response_body: str | None = None,
    decrypted_body_encoding: str = "text",
    comment: str | None = None,
    marked: bool | None = None,
    tags: list[str] | None = None,
    use_modified: bool = True,
) -> dict[str, Any]:
    """Flow operations. Actions: replay, resume, kill, update, create, send. Use tool_info('flow_action') for details."""
    try:
        if action == "replay":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            return _flow_replay(flow_id=flow_id, use_modified=use_modified)
        if action == "resume":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            return _flow_resume(flow_id=flow_id)
        if action == "kill":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            return _flow_kill(flow_id=flow_id)
        if action == "update":
            if flow_id is None:
                return {"success": False, "error": "flow_id is required"}
            return _flow_update(
                flow_id=flow_id,
                request_method=request_method,
                request_path=request_path,
                request_headers=request_headers,
                request_body=request_body,
                request_body_encoding=request_body_encoding,
                response_status=response_status,
                response_reason=response_reason,
                response_headers=response_headers,
                response_body=response_body,
                response_body_encoding=response_body_encoding,
                decrypted_request_body=decrypted_request_body,
                decrypted_response_body=decrypted_response_body,
                decrypted_body_encoding=decrypted_body_encoding,
                comment=comment,
                marked=marked,
                tags=tags,
            )
        if action == "create":
            if method is None or url is None:
                return {"success": False, "error": "method and url are required"}
            return _flow_create(
                method=method,
                url=url,
                headers=headers,
                body=body,
                body_encoding=encoding,
                comment=comment,
            )
        if action == "send":
            if method is None or url is None:
                return {"success": False, "error": "method and url are required"}
            return _request_send(
                method=method,
                url=url,
                headers=headers,
                body=body,
                body_encoding=encoding,
            )
        return {"success": False, "error": f"Unknown flow action: {action}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def rule_ctl(
    cmd: Literal["list", "add", "delete", "clear"],
    proxy_id: Literal["main", "aux"] = "main",
    rule: dict[str, Any] | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Automatic rules. Commands: list, add, delete, clear. Use tool_info('rule_ctl') for details."""
    try:
        target = _get_proxy_by_id(proxy_id)
        if cmd == "list":
            rules = target.list_rules()
            return {"success": True, "rules": [r.model_dump(exclude_none=True) for r in rules]}
        if cmd == "add":
            if rule is None:
                return {"success": False, "error": "rule is required"}
            rule_obj = Rule(**rule)
            target.add_rule(rule_obj)
            return {"success": True, "rule": rule_obj.model_dump(exclude_none=True)}
        if cmd == "delete":
            if rule_id is None:
                return {"success": False, "error": "rule_id is required"}
            if target.delete_rule(rule_id):
                return {"success": True}
            return {"success": False, "error": f"Rule with id {rule_id} not found"}
        if cmd == "clear":
            count = target.clear_rules()
            return {"success": True, "cleared": count}
        return {"success": False, "error": f"Unknown rule command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def capture_rule_ctl(
    cmd: Literal["list", "add", "delete", "clear"],
    proxy_id: Literal["main", "aux"] = "main",
    rule: dict[str, Any] | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Capture rules. Commands: list, add, delete, clear. Use tool_info('capture_rule_ctl') for details."""
    try:
        target = _get_proxy_by_id(proxy_id)
        if cmd == "list":
            rules = target.list_capture_rules()
            return {"success": True, "rules": [r.model_dump(exclude_none=True) for r in rules]}
        if cmd == "add":
            if rule is None:
                return {"success": False, "error": "rule is required"}
            rule_obj = CaptureRule(**rule)
            target.add_capture_rule(rule_obj)
            return {"success": True, "rule": rule_obj.model_dump(exclude_none=True)}
        if cmd == "delete":
            if rule_id is None:
                return {"success": False, "error": "rule_id is required"}
            if target.delete_capture_rule(rule_id):
                return {"success": True}
            return {
                "success": False,
                "error": f"Capture rule with id {rule_id} not found",
            }
        if cmd == "clear":
            count = target.clear_capture_rules()
            return {"success": True, "cleared": count}
        return {"success": False, "error": f"Unknown capture rule command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def mock_server_ctl(
    cmd: Literal["start", "add", "stop", "status"],
    flow_ids: list[int] | None = None,
    ignore_host: bool = False,
    ignore_port: bool = False,
    ignore_params: list[str] | None = None,
    ignore_content: bool = False,
    extra: str = "forward",
) -> dict[str, Any]:
    """Mock server. Commands: start, add, stop, status. Use tool_info('mock_server_ctl') for details."""
    try:
        if cmd == "start":
            return _mock_server_start(
                flow_ids=flow_ids,
                ignore_host=ignore_host,
                ignore_port=ignore_port,
                ignore_params=ignore_params,
                ignore_content=ignore_content,
                extra=extra,
            )
        if cmd == "add":
            if not flow_ids:
                return {"success": False, "error": "flow_ids is required"}
            return _mock_server_add_flows(flow_ids=flow_ids)
        if cmd == "stop":
            if not proxy_manager.is_running:
                return {"success": True, "message": "Proxy is not running"}
            proxy_manager.call("replay.server.stop")
            return {"success": True}
        if cmd == "status":
            if not proxy_manager.is_running:
                return {"success": False, "error": "Proxy is not running."}
            count = proxy_manager.call("replay.server.count")
            return {"success": True, "mocked_flows": count}
        return {"success": False, "error": f"Unknown mock server command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def map_local_ctl(
    cmd: Literal["list", "add", "delete", "clear"],
    rule: MapLocalRule | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Map local files. Commands: list, add, delete, clear. Use tool_info('map_local_ctl') for details."""
    try:
        if cmd == "list":
            rules = proxy_manager.list_map_local_rules()
            return {"success": True, "rules": [r.model_dump(exclude_none=True) for r in rules]}
        if cmd == "add":
            if rule is None:
                return {"success": False, "error": "rule is required"}
            rule_obj = MapLocalRule(**rule)
            proxy_manager.add_map_local_rule(rule_obj)
            return {"success": True, "rule": rule_obj.model_dump(exclude_none=True)}
        if cmd == "delete":
            if rule_id is None:
                return {"success": False, "error": "rule_id is required"}
            if proxy_manager.delete_map_local_rule(rule_id):
                return {"success": True}
            return {
                "success": False,
                "error": f"map_local rule with id {rule_id} not found",
            }
        if cmd == "clear":
            count = proxy_manager.clear_map_local_rules()
            return {"success": True, "cleared": count}
        return {"success": False, "error": f"Unknown map_local command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def map_remote_ctl(
    cmd: Literal["list", "add", "delete", "clear"],
    rule: MapRemoteRule | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Map remote URLs. Commands: list, add, delete, clear. Use tool_info('map_remote_ctl') for details."""
    try:
        if cmd == "list":
            rules = proxy_manager.list_map_remote_rules()
            return {"success": True, "rules": [r.model_dump(exclude_none=True) for r in rules]}
        if cmd == "add":
            if rule is None:
                return {"success": False, "error": "rule is required"}
            rule_obj = MapRemoteRule(**rule)
            proxy_manager.add_map_remote_rule(rule_obj)
            return {"success": True, "rule": rule_obj.model_dump(exclude_none=True)}
        if cmd == "delete":
            if rule_id is None:
                return {"success": False, "error": "rule_id is required"}
            if proxy_manager.delete_map_remote_rule(rule_id):
                return {"success": True}
            return {
                "success": False,
                "error": f"map_remote rule with id {rule_id} not found",
            }
        if cmd == "clear":
            count = proxy_manager.clear_map_remote_rules()
            return {"success": True, "cleared": count}
        return {"success": False, "error": f"Unknown map_remote command: {cmd}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def tool_info(tool_name: str, cmd: str | None = None) -> dict[str, Any]:
    """Query detailed documentation for any tool. Use this when you need parameter details or examples."""
    return get_tool_info(tool_name, cmd)


def main() -> None:
    """Run the MCP server over stdio or SSE."""
    parser = argparse.ArgumentParser(description="mitmproxy-mcp MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind when using SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port to bind when using SSE transport (default: 8081)",
    )
    args = parser.parse_args()

    if args.transport == "sse":
        _configure_mcp_settings(args.host, args.port)
        logger.info("Starting SSE server on %s:%d", args.host, args.port)
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
