"""Tests for Tier 2 MCP resources."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from mitmproxy import http

from mitmproxy_mcp.crypto import CryptoAddon, LoadedCryptoScript
from mitmproxy_mcp.events import EventBuffer
from mitmproxy_mcp.proxy import CaptureAddon, ProxyManager
from mitmproxy_mcp.resources import (
    ca_status_resource,
    crypto_scripts_resource,
    events_latest_resource,
)
from mitmproxy_mcp.rules import Action, Rule, RulesAddon
from mitmproxy_mcp.server import mcp, proxy_manager, store
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.utils import create_http_flow
from mitmproxy_mcp.websocket_rules import WebSocketRule, WebSocketRulesAddon


@pytest.mark.asyncio
async def test_list_resources_includes_tier2() -> None:
    resources = await mcp.list_resources()
    uris = [str(r.uri) for r in resources]
    assert "mitmproxy://events/latest" in uris
    assert "mitmproxy://crypto/scripts" in uris
    assert "mitmproxy://ca/status" in uris


@pytest.mark.asyncio
async def test_events_latest_initially_empty() -> None:
    proxy_manager.event_buffer.clear()
    contents = await mcp.read_resource("mitmproxy://events/latest")
    assert len(contents) == 1
    assert contents[0].content == "[]"


@pytest.mark.asyncio
async def test_events_latest_after_proxy_start_stop() -> None:
    proxy_manager.event_buffer.clear()
    proxy_manager.event_buffer.emit("proxy:started", {"host": "127.0.0.1", "port": 8080})
    proxy_manager.event_buffer.emit("proxy:stopped", {})

    contents = await mcp.read_resource("mitmproxy://events/latest")
    data = contents[0].content
    assert "proxy:started" in data
    assert "proxy:stopped" in data


@pytest.mark.asyncio
async def test_events_latest_after_flow_capture() -> None:
    store.clear()
    proxy_manager.event_buffer.clear()
    flow = create_http_flow("GET", "http://example.com/api", body=b"x")
    flow.response = http.Response.make(200, b"ok")
    addon = CaptureAddon(store, event_buffer=proxy_manager.event_buffer)
    addon.response(flow)

    contents = await mcp.read_resource("mitmproxy://events/latest")
    data = contents[0].content
    assert "flow:captured" in data
    assert '"method": "GET"' in data
    assert '"host": "example.com"' in data


@pytest.mark.asyncio
async def test_events_latest_limit() -> None:
    buffer = EventBuffer(max_size=30)
    for i in range(25):
        buffer.emit("flow:captured", {"store_id": i})

    result = events_latest_resource(buffer, limit=10)
    assert len(result) == 10
    assert result[0]["store_id"] == 24
    assert result[-1]["store_id"] == 15


@pytest.mark.asyncio
async def test_crypto_scripts_resource() -> None:
    fresh_store = FlowStore()
    addon = CryptoAddon(fresh_store, event_buffer=EventBuffer())
    # Simulate a loaded script without reading a real file.
    addon._scripts.clear()
    addon._scripts.append(
        LoadedCryptoScript(
            id="demo",
            name="Demo Handler",
            path="/tmp/demo.py",
            handler=object(),
            loaded_at=0.0,
            error_count=2,
            last_error="bad key",
        )
    )

    pm = ProxyManager(fresh_store)
    pm.crypto_addon = addon

    contents = crypto_scripts_resource(pm)
    assert len(contents) == 1
    assert contents[0]["id"] == "demo"
    assert contents[0]["error_count"] == 2
    assert contents[0]["last_error"] == "bad key"


@pytest.mark.asyncio
async def test_ca_status_resource() -> None:
    contents = await mcp.read_resource("mitmproxy://ca/status")
    data = contents[0].content
    assert '"verify_upstream"' in data
    assert '"upstream_ca_file"' in data
    assert '"client_cert"' in data
    assert '"proxy_running"' in data


def test_rule_matched_event() -> None:
    buffer = EventBuffer()
    addon = RulesAddon(event_buffer=buffer)
    rule = Rule(
        id="r1",
        name="test",
        filter="~u example.com",
        phase="request",
        actions=[Action(type="set_header", target="request", name="X-Test", value="1")],
    )
    addon.add_rule(rule)

    flow = create_http_flow("GET", "http://example.com/path")
    asyncio.run(addon.request(flow))

    events = buffer.latest()
    assert len(events) == 1
    assert events[0]["type"] == "rule:matched"
    assert events[0]["rule_ids"] == ["r1"]


def test_websocket_rule_matched_event_dropped() -> None:
    buffer = EventBuffer()
    addon = WebSocketRulesAddon(event_buffer=buffer)
    rule = WebSocketRule(
        id="ws1",
        name="drop ping",
        action="drop",
    )
    addon.add_rule(rule)

    flow = create_http_flow("GET", "http://example.com/ws")
    msg = MagicMock()
    msg.from_client = True
    msg.is_text = True
    msg.content = b"ping"
    msg.text = "ping"
    msg.metadata = None
    flow.websocket = MagicMock()
    flow.websocket.messages = [msg]
    addon.websocket_message(flow)

    events = buffer.latest()
    assert len(events) == 1
    assert events[0]["type"] == "websocket_rule:matched"
    assert events[0]["rule_id"] == "ws1"
    assert events[0]["dropped"] is True
