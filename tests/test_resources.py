"""Tests for MCP resources."""

from __future__ import annotations

import asyncio

import pytest

from mitmproxy_mcp.server import mcp, store
from mitmproxy_mcp.utils import create_http_flow


@pytest.mark.asyncio
async def test_list_resources() -> None:
    resources = await mcp.list_resources()
    uris = [str(r.uri) for r in resources]
    assert "mitmproxy://proxy/status" in uris
    assert "mitmproxy://flows/latest" in uris
    assert "mitmproxy://config/rules" in uris
    assert "mitmproxy://events/latest" in uris
    assert "mitmproxy://crypto/scripts" in uris
    assert "mitmproxy://ca/status" in uris

    templates = await mcp.list_resource_templates()
    assert any(t.uriTemplate == "mitmproxy://flows/{flow_id}" for t in templates)


@pytest.mark.asyncio
async def test_proxy_status_resource() -> None:
    contents = await mcp.read_resource("mitmproxy://proxy/status")
    assert len(contents) == 1
    data = contents[0].content
    assert '"running":' in data
    assert '"capture_count":' in data
    assert '"ca":' in data


@pytest.mark.asyncio
async def test_flows_latest_is_summary() -> None:
    store.clear()
    flow = create_http_flow("POST", "http://api.example.com/login", body=b"secret")
    store.add(flow)

    contents = await mcp.read_resource("mitmproxy://flows/latest")
    assert len(contents) == 1
    data = contents[0].content
    assert "secret" not in data  # body must not appear in the summary
    assert '"method": "POST"' in data
    assert '"host": "api.example.com"' in data
    assert '"path": "/login"' in data


@pytest.mark.asyncio
async def test_flow_detail_resource() -> None:
    store.clear()
    flow = create_http_flow("GET", "http://example.com/api", body=b"hello")
    store_id = store.add(flow)

    contents = await mcp.read_resource(f"mitmproxy://flows/{store_id}")
    assert len(contents) == 1
    data = contents[0].content
    assert f'"store_id": {store_id}' in data
    assert '"method": "GET"' in data
    assert '"content": "hello"' in data


@pytest.mark.asyncio
async def test_flow_detail_not_found() -> None:
    with pytest.raises(ValueError):
        await mcp.read_resource("mitmproxy://flows/99999")


@pytest.mark.asyncio
async def test_config_rules_resource() -> None:
    contents = await mcp.read_resource("mitmproxy://config/rules")
    assert len(contents) == 1
    data = contents[0].content
    assert '"automatic_rules"' in data
    assert '"capture_rules"' in data
    assert '"map_local_rules"' in data
    assert '"map_remote_rules"' in data
    assert '"crypto_scripts"' in data
    assert '"websocket_rules"' in data
