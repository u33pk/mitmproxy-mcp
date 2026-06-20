"""Integration tests for WebSocket capture."""

from __future__ import annotations

import asyncio
import time

import pytest
import websockets

from mitmproxy_mcp.server import http_ctl, proxy_ctl, websocket_ctl


@pytest.fixture(autouse=True)
def _cleanup():
    try:
        proxy_ctl(cmd="stop")
        http_ctl(cmd="clear")
    except Exception:
        pass
    yield
    try:
        http_ctl(cmd="clear")
        proxy_ctl(cmd="stop")
    except Exception:
        pass


async def _echo_server(websocket):
    async for message in websocket:
        await websocket.send(f"echo: {message}")


async def _run_test() -> None:
    server_port = 19101
    proxy_port = 18151

    server = await websockets.serve(_echo_server, "127.0.0.1", server_port)
    try:
        r = proxy_ctl(cmd="start", port=proxy_port)
        assert r["success"] is True

        async with websockets.connect(
            f"ws://127.0.0.1:{server_port}/ws",
            proxy=f"http://127.0.0.1:{proxy_port}",
        ) as ws:
            await ws.send("hello")
            response = await ws.recv()
            assert response == "echo: hello"

        # Give mitmproxy a moment to process the close frame.
        time.sleep(1)

        r = websocket_ctl(cmd="list")
        assert r["total"] >= 1, f"Expected at least one WebSocket flow, got {r}"
        ws_flow = r["flows"][0]
        assert ws_flow["is_websocket"] is True
        assert ws_flow["request"]["method"] == "GET"

        fid = ws_flow["store_id"]
        r = http_ctl(cmd="get", flow_id=fid)
        assert r["success"] is True
        ws_data = r["flow"]["websocket"]
        assert ws_data is not None

        texts = [m["text"] for m in ws_data["messages"] if m["type"] == "text"]
        assert "hello" in texts
        assert "echo: hello" in texts

        directions = [(m["from_client"], m["text"]) for m in ws_data["messages"] if m["type"] == "text"]
        assert (True, "hello") in directions
        assert (False, "echo: hello") in directions
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.integration
def test_websocket_capture() -> None:
    """A WebSocket conversation is captured as a single HTTPFlow with messages."""
    asyncio.run(_run_test())


if __name__ == "__main__":
    test_websocket_capture()
    print("WebSocket integration test passed.")
