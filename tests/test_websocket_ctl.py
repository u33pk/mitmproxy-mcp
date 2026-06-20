"""Tests for mitmproxy_mcp WebSocket management."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
import threading
import time
import websockets

from mitmproxy import http
from mitmproxy.connection import Client, Server
from mitmproxy.websocket import WebSocketData, WebSocketMessage

from mitmproxy_mcp.proxy import ProxyManager
from mitmproxy_mcp.server import proxy_manager, store, websocket_ctl
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.websocket_rules import WebSocketRule, WebSocketRulesAddon


def _make_ws_flow(url: str = "ws://example.com/ws") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    flow.response = http.Response.make(101, b"", {"Upgrade": "websocket"})
    flow.websocket = WebSocketData()
    return flow


def test_rule_model_validation() -> None:
    rule = WebSocketRule(id="r1", action="drop")
    assert rule.action == "drop"

    with pytest.raises(ValueError):
        WebSocketRule(id="r2", action="replace")

    with pytest.raises(ValueError):
        WebSocketRule(id="r3", action="replace_regex", replacement="x")


def test_rule_flow_filter() -> None:
    rule = WebSocketRule(id="r1", action="drop", flow_filter="~d example.com")
    matching = _make_ws_flow("ws://example.com/ws")
    non_matching = _make_ws_flow("ws://other.com/ws")

    msg = WebSocketMessage(type=1, from_client=True, content=b"hello")
    assert rule._matches_flow(matching) is True
    assert rule._matches_flow(non_matching) is False
    assert rule.apply(matching, msg) is True
    assert msg.dropped is True


def test_rule_direction() -> None:
    rule = WebSocketRule(id="r1", action="drop", direction="server")
    flow = _make_ws_flow()
    client_msg = WebSocketMessage(type=1, from_client=True, content=b"hi")
    server_msg = WebSocketMessage(type=1, from_client=False, content=b"ho")

    assert rule.apply(flow, client_msg) is False
    assert client_msg.dropped is False
    assert rule.apply(flow, server_msg) is True
    assert server_msg.dropped is True


def test_rule_message_filter_regex() -> None:
    rule = WebSocketRule(
        id="r1",
        action="replace",
        message_filter="ping",
        replacement="pong",
    )
    flow = _make_ws_flow()
    msg = WebSocketMessage(type=1, from_client=True, content=b"ping")

    assert rule.apply(flow, msg) is False
    assert msg.text == "pong"


def test_rule_replace_regex_text() -> None:
    rule = WebSocketRule(
        id="r1",
        action="replace_regex",
        message_filter="user=\\w+",
        replacement_regex="user=\\w+",
        replacement="user=anonymous",
    )
    flow = _make_ws_flow()
    msg = WebSocketMessage(type=1, from_client=True, content=b"hello user=alice")

    assert rule.apply(flow, msg) is False
    assert msg.text == "hello user=anonymous"


def test_rule_replace_binary() -> None:
    rule = WebSocketRule(
        id="r1",
        action="replace",
        replacement="cG9uZw==",  # base64 of "pong"
    )
    flow = _make_ws_flow()
    msg = WebSocketMessage(type=2, from_client=True, content=b"ping")

    assert rule.apply(flow, msg) is False
    assert msg.content == b"pong"


def test_addon_applies_rules() -> None:
    addon = WebSocketRulesAddon()
    rule = WebSocketRule(id="r1", action="drop", message_filter="drop-me")
    addon.add_rule(rule)

    flow = _make_ws_flow()
    kept = WebSocketMessage(type=1, from_client=True, content=b"keep")
    dropped = WebSocketMessage(type=1, from_client=True, content=b"drop-me")
    flow.websocket.messages.append(kept)
    addon.websocket_message(flow)
    assert kept.dropped is False

    flow.websocket.messages.append(dropped)
    addon.websocket_message(flow)
    assert dropped.dropped is True


def test_websocket_ctl_list_and_get() -> None:
    store.clear()
    flow = _make_ws_flow()
    sid = store.add(flow)

    r = websocket_ctl(cmd="list")
    assert r["success"] is True
    assert r["total"] == 1

    r = websocket_ctl(cmd="get", flow_id=sid)
    assert r["success"] is True
    assert r["flow"]["is_websocket"] is True

    non_ws = http.HTTPFlow(
        Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080)),
        Server(address=("example.com", 80)),
    )
    non_ws.request = http.Request.make("GET", "http://example.com/")
    non_ws_sid = store.add(non_ws)
    r = websocket_ctl(cmd="get", flow_id=non_ws_sid)
    assert r["success"] is False
    store.clear()


def test_websocket_ctl_rule_management() -> None:
    proxy_manager.clear_websocket_rules()
    rule = {
        "id": "test-rule",
        "action": "drop",
        "message_filter": "secret",
    }
    r = websocket_ctl(cmd="add_rule", rule=rule)
    assert r["success"] is True
    assert len(proxy_manager.list_websocket_rules()) == 1

    r = websocket_ctl(cmd="list_rules")
    assert r["success"] is True
    assert len(r["rules"]) == 1

    r = websocket_ctl(cmd="delete_rule", rule_id="test-rule")
    assert r["success"] is True
    assert len(proxy_manager.list_websocket_rules()) == 0

    r = websocket_ctl(cmd="clear_rules")
    assert r["success"] is True


def _run_echo_server(port: int, stop_event: threading.Event) -> None:
    async def echo(websocket):
        async for message in websocket:
            await websocket.send(f"echo: {message}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def start() -> Any:
        return await websockets.serve(echo, "127.0.0.1", port)

    server = loop.run_until_complete(start())
    while not stop_event.is_set():
        loop.run_until_complete(asyncio.sleep(0.1))
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


@pytest.mark.integration
def test_websocket_connect_and_capture() -> None:
    """Start a local echo server, connect through mitmproxy, and verify capture."""
    from mitmproxy_mcp.server import proxy_ctl

    stop_event = threading.Event()
    server_thread = threading.Thread(target=_run_echo_server, args=(19700, stop_event), daemon=True)
    server_thread.start()
    time.sleep(0.3)
    try:
        proxy_ctl(cmd="start", port=19701)
        try:
            r = websocket_ctl(
                cmd="connect",
                url="ws://127.0.0.1:19700/",
                messages=["hello"],
                wait_for=1,
                timeout=5,
            )
            assert r["success"] is True, r.get("error")
            assert r["sent"] == ["hello"]
            assert r["received"] == ["echo: hello"]
            assert r["flow_id"] is not None

            flow_r = websocket_ctl(cmd="get", flow_id=r["flow_id"])
            assert flow_r["success"] is True
            msgs = flow_r["flow"]["websocket"]["messages"]
            texts = [m["text"] for m in msgs if m["type"] == "text"]
            assert "hello" in texts
            assert "echo: hello" in texts
        finally:
            proxy_ctl(cmd="stop")
    finally:
        stop_event.set()
        server_thread.join(timeout=5)


@pytest.mark.integration
def test_websocket_inject() -> None:
    """Inject a message into an active WebSocket connection."""
    from mitmproxy_mcp.server import proxy_ctl

    def run_client(port: int, proxy_port: int, stop_event: threading.Event) -> None:
        async def receive_loop(websocket):
            async for _msg in websocket:
                pass

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def start() -> Any:
            return await websockets.connect(
                f"ws://127.0.0.1:{port}/",
                proxy=f"http://127.0.0.1:{proxy_port}",
                open_timeout=5,
            )

        ws = loop.run_until_complete(start())
        task = loop.create_task(receive_loop(ws))
        while not stop_event.is_set():
            loop.run_until_complete(asyncio.sleep(0.1))
        task.cancel()
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
        try:
            loop.run_until_complete(asyncio.wait_for(ws.close(), timeout=2))
        except Exception:
            pass
        loop.close()

    stop_event = threading.Event()
    server_thread = threading.Thread(target=_run_echo_server, args=(19702, stop_event), daemon=True)
    server_thread.start()
    time.sleep(0.3)

    client_stop = threading.Event()
    client_thread = threading.Thread(
        target=run_client, args=(19702, 19703, client_stop), daemon=True
    )

    try:
        proxy_ctl(cmd="start", port=19703)
        client_thread.start()
        try:
            time.sleep(0.5)
            flows = websocket_ctl(cmd="list")["flows"]
            # Find the flow matching this test's server port.
            flow_id = None
            for f in reversed(flows):
                if f["request"]["host"] == "127.0.0.1" and f["request"]["port"] == 19702:
                    flow_id = f["store_id"]
                    break
            assert flow_id is not None

            r = websocket_ctl(cmd="inject", flow_id=flow_id, message="injected", to_client=False)
            assert r["success"] is True, r.get("error")

            time.sleep(0.5)

            flow_r = websocket_ctl(cmd="get", flow_id=flow_id)
            texts = [m["text"] for m in flow_r["flow"]["websocket"]["messages"] if m["type"] == "text"]
            assert "injected" in texts
            assert "echo: injected" in texts

            # Close the client before stopping the proxy to avoid abrupt teardown.
            client_stop.set()
            client_thread.join(timeout=5)
        finally:
            proxy_ctl(cmd="stop")
    finally:
        stop_event.set()
        server_thread.join(timeout=5)


@pytest.mark.integration
def test_websocket_replace_rule() -> None:
    """A replace rule modifies echoed WebSocket messages."""
    from mitmproxy_mcp.server import proxy_ctl

    stop_event = threading.Event()
    server_thread = threading.Thread(target=_run_echo_server, args=(19704, stop_event), daemon=True)
    server_thread.start()
    time.sleep(0.3)
    try:
        proxy_ctl(cmd="start", port=19705)
        try:
            websocket_ctl(
                cmd="add_rule",
                rule={
                    "id": "mod-echo",
                    "direction": "server",
                    "action": "replace_regex",
                    "message_filter": "echo: ",
                    "replacement_regex": "echo: ",
                    "replacement": "replaced: ",
                },
            )
            r = websocket_ctl(
                cmd="connect",
                url="ws://127.0.0.1:19704/",
                messages=["hello"],
                wait_for=1,
                timeout=5,
            )
            assert r["success"] is True
            assert r["received"] == ["replaced: hello"]
        finally:
            proxy_ctl(cmd="stop")
            websocket_ctl(cmd="clear_rules")
    finally:
        stop_event.set()
        server_thread.join(timeout=5)
