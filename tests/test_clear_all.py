"""Tests for mitmproxy_mcp.clear_all."""

from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.proxy import CaptureRule, ProxyManager
from mitmproxy_mcp.rules import Action, Rule
from mitmproxy_mcp.store import FlowStore


def _make_flow(url: str = "http://example.com/") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def test_clear_all_clears_everything() -> None:
    store = FlowStore()
    manager = ProxyManager(store)

    store.add(_make_flow())
    manager.add_rule(Rule(id="r1", filter="~u example.com", actions=[Action(type="kill")]))
    manager.add_capture_rule(CaptureRule(id="c1", filter="~u example.com", action="include"))

    assert store.count() == 1
    assert len(manager.list_rules()) == 1
    assert len(manager.list_capture_rules()) == 1

    result = manager.clear_all()

    assert result["success"] is True
    assert result["cleared_flows"] == 1
    assert result["cleared_rules"] == 1
    assert result["cleared_capture_rules"] == 1
    assert store.count() == 0
    assert len(manager.list_rules()) == 0
    assert len(manager.list_capture_rules()) == 0


def test_clear_all_without_proxy_does_not_fail() -> None:
    store = FlowStore()
    manager = ProxyManager(store)
    result = manager.clear_all()
    assert result["success"] is True
    assert "proxy_stopped" not in result
