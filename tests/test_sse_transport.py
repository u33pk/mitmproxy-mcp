"""Tests for SSE transport support."""

from __future__ import annotations

import asyncio
import sys

import pytest
from mcp import ClientSession
from mcp.client.sse import sse_client

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # pragma: no cover


@pytest.mark.asyncio
async def test_sse_server_lists_tools() -> None:
    """Start the MCP server in SSE mode and verify a client can list tools."""
    from mitmproxy_mcp.server import mcp

    host = "127.0.0.1"
    port = 18082
    mcp.settings.host = host
    mcp.settings.port = port

    server_task = asyncio.create_task(mcp.run_sse_async())

    # Wait for uvicorn to come up
    for _ in range(50):
        await asyncio.sleep(0.1)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            break
        except OSError:
            continue
    else:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        raise RuntimeError("SSE server did not start in time")

    try:
        async with sse_client(f"http://{host}:{port}/sse") as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                tool_names = {t.name for t in result.tools}
                assert "proxy_ctl" in tool_names
                assert "http_ctl" in tool_names
                assert "websocket_ctl" in tool_names
                assert "tool_info" in tool_names
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
