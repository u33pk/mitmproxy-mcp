"""MCP resources exposing mitmproxy state for direct reading by clients."""

from __future__ import annotations

from typing import Any

from mitmproxy_mcp.events import EventBuffer
from mitmproxy_mcp.models import flow_to_model
from mitmproxy_mcp.proxy import ProxyManager
from mitmproxy_mcp.store import FlowStore


PROXY_STATUS_URI = "mitmproxy://proxy/status"
FLOWS_LATEST_URI = "mitmproxy://flows/latest"
FLOW_DETAIL_TEMPLATE = "mitmproxy://flows/{flow_id}"
CONFIG_RULES_URI = "mitmproxy://config/rules"
EVENTS_LATEST_URI = "mitmproxy://events/latest"
CRYPTO_SCRIPTS_URI = "mitmproxy://crypto/scripts"
CA_STATUS_URI = "mitmproxy://ca/status"


def proxy_status_resource(proxy_manager: ProxyManager) -> dict[str, Any]:
    """Return a concise summary of the proxy state."""
    ca = proxy_manager._ca_config
    return {
        "running": proxy_manager.is_running,
        "listen_host": proxy_manager.listen_host,
        "listen_port": proxy_manager.listen_port,
        "capture_count": proxy_manager.store.count(),
        "websocket_count": proxy_manager.store.count(websocket_only=True),
        "wireguard_mode": proxy_manager.wireguard_config() if proxy_manager.is_running else None,
        "ca": {
            "verify_upstream": ca.verify_upstream,
            "has_upstream_ca": bool(ca.upstream_ca_file or ca.upstream_ca_confdir),
            "has_client_cert": bool(ca.client_cert),
        },
    }


def flows_latest_resource(
    store: FlowStore,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return a lightweight list of recent flows.

    Only index fields are included to keep context usage low. Use
    ``mitmproxy://flows/{id}`` to read full flow details.
    """
    items = store.list(offset=offset, limit=limit)
    return [
        {
            "store_id": sid,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "status": flow.response.status_code if flow.response else None,
            "is_websocket": flow.websocket is not None,
            "timestamp_start": flow.request.timestamp_start,
        }
        for sid, flow in items
    ]


def flow_detail_resource(store: FlowStore, store_id: int) -> dict[str, Any]:
    """Return the full FlowModel for a single captured flow."""
    flow = store.get(store_id)
    if flow is None:
        raise ValueError(f"Flow with id {store_id} not found")
    return flow_to_model(flow, store_id=store_id).model_dump()


def config_rules_resource(proxy_manager: ProxyManager) -> dict[str, Any]:
    """Return a snapshot of all active configuration rules and scripts."""
    return {
        "automatic_rules": [r.model_dump(exclude_none=True) for r in proxy_manager.list_rules()],
        "capture_rules": [r.model_dump(exclude_none=True) for r in proxy_manager.list_capture_rules()],
        "map_local_rules": [r.model_dump(exclude_none=True) for r in proxy_manager.list_map_local_rules()],
        "map_remote_rules": [r.model_dump(exclude_none=True) for r in proxy_manager.list_map_remote_rules()],
        "crypto_scripts": proxy_manager.list_crypto_scripts(),
        "websocket_rules": [r.model_dump(exclude_none=True) for r in proxy_manager.list_websocket_rules()],
    }


def events_latest_resource(event_buffer: EventBuffer, limit: int = 10) -> list[dict[str, Any]]:
    """Return the most recent lightweight events from the event buffer."""
    return event_buffer.latest(limit=limit)


def crypto_scripts_resource(proxy_manager: ProxyManager) -> list[dict[str, Any]]:
    """Return a summary of all loaded crypto scripts, including error state."""
    return proxy_manager.list_crypto_scripts()


def ca_status_resource(proxy_manager: ProxyManager) -> dict[str, Any]:
    """Return the current CA/certificate configuration."""
    return proxy_manager.ca_status()
