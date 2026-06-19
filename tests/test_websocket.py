"""Unit tests for WebSocket model serialization."""

from __future__ import annotations

import base64

from mitmproxy import http
from mitmproxy.connection import Client, Server
from mitmproxy.websocket import WebSocketData, WebSocketMessage

from mitmproxy_mcp.models import (
    flow_to_model,
    websocket_message_to_model,
    websocket_to_model,
)


def _make_flow(url: str = "http://example.com/") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def test_websocket_message_text() -> None:
    msg = WebSocketMessage(1, from_client=True, content=b'{"hello":"world"}')
    model = websocket_message_to_model(msg)
    assert model.from_client is True
    assert model.type == "text"
    assert model.content == '{"hello":"world"}'
    assert model.text == '{"hello":"world"}'
    assert model.content_encoding == "text"
    assert model.content_length == 17


def test_websocket_message_binary() -> None:
    raw = b"\x00\x01\x02\x03"
    msg = WebSocketMessage(2, from_client=False, content=raw)
    model = websocket_message_to_model(msg)
    assert model.from_client is False
    assert model.type == "binary"
    assert model.content == base64.b64encode(raw).decode("ascii")
    assert model.text is None
    assert model.content_encoding == "base64"
    assert model.content_length == 4


def test_websocket_message_truncation() -> None:
    msg = WebSocketMessage(1, from_client=True, content=b"a" * 100)
    model = websocket_message_to_model(msg, max_content_size=20)
    assert model.content.endswith("\n…(truncated)")
    assert model.content_length == 100


def test_flow_to_model_detects_websocket() -> None:
    flow = _make_flow()
    flow.websocket = WebSocketData()
    flow.websocket.messages.append(
        WebSocketMessage(1, from_client=True, content=b"ping")
    )
    model = flow_to_model(flow, store_id=7)
    assert model.is_websocket is True
    assert model.websocket is not None
    assert len(model.websocket.messages) == 1
    assert model.websocket.messages[0].text == "ping"


def test_flow_to_model_without_websocket() -> None:
    flow = _make_flow()
    model = flow_to_model(flow, store_id=1)
    assert model.is_websocket is False
    assert model.websocket is None


def test_websocket_data_model() -> None:
    ws = WebSocketData()
    ws.messages.append(WebSocketMessage(1, from_client=True, content=b"hello"))
    ws.closed_by_client = True
    ws.close_code = 1000
    ws.close_reason = "normal closure"
    model = websocket_to_model(ws)
    assert len(model.messages) == 1
    assert model.closed_by_client is True
    assert model.close_code == 1000
    assert model.close_reason == "normal closure"
