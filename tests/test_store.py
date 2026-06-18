"""Tests for mitmproxy_mcp.store."""

from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.store import FlowStore


def _make_flow(url: str = "http://example.com/") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def test_add_and_get() -> None:
    store = FlowStore()
    flow = _make_flow()
    sid = store.add(flow)
    assert sid == 1
    assert store.get(sid) is flow


def test_delete() -> None:
    store = FlowStore()
    sid = store.add(_make_flow())
    assert store.delete(sid) is True
    assert store.delete(sid) is False


def test_list_filter_host() -> None:
    store = FlowStore()
    store.add(_make_flow("http://foo.com/a"))
    store.add(_make_flow("http://bar.com/b"))
    items = store.list(host="foo.com")
    assert len(items) == 1
    assert items[0][1].request.host == "foo.com"


def test_list_filter_method() -> None:
    store = FlowStore()
    store.add(_make_flow("http://example.com/"))
    assert len(store.list(method="GET")) == 1
    assert len(store.list(method="POST")) == 0


def test_clear() -> None:
    store = FlowStore()
    store.add(_make_flow())
    assert store.clear() == 1
    assert store.count() == 0
