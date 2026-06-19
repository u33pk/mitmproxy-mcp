"""Tests for mitmproxy_mcp.capture rules in proxy.py."""

import pytest
from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.proxy import CaptureAddon, CaptureRule
from mitmproxy_mcp.store import FlowStore


def _make_flow(url: str = "http://example.com/", method: str = "GET") -> http.HTTPFlow:
    req = http.Request.make(method, url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


# ---------------------------------------------------------------------------
# CaptureRule validation
# ---------------------------------------------------------------------------


def test_capture_rule_valid() -> None:
    rule = CaptureRule(id="r1", filter="~u example.com", action="include")
    assert rule.action == "include"
    assert rule._compiled_filter is not None


def test_capture_rule_invalid_filter() -> None:
    with pytest.raises(ValueError):
        CaptureRule(id="r1", filter="~~~invalid", action="include")


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------


def test_add_and_list_rules() -> None:
    addon = CaptureAddon(FlowStore())
    rule = CaptureRule(id="r1", filter="~u example.com", action="include")
    addon.add_rule(rule)
    assert len(addon.list_rules()) == 1


def test_add_rule_replaces_same_id() -> None:
    addon = CaptureAddon(FlowStore())
    addon.add_rule(CaptureRule(id="r1", filter="~u example.com", action="include"))
    addon.add_rule(CaptureRule(id="r1", filter="~u example.org", action="exclude"))
    rules = addon.list_rules()
    assert len(rules) == 1
    assert rules[0].action == "exclude"


def test_update_rule() -> None:
    addon = CaptureAddon(FlowStore())
    addon.add_rule(CaptureRule(id="r1", filter="~u example.com", action="include"))
    updated = addon.update_rule("r1", {"action": "exclude"})
    assert updated is not None
    assert updated.action == "exclude"
    assert addon.list_rules()[0].action == "exclude"


def test_delete_rule() -> None:
    addon = CaptureAddon(FlowStore())
    addon.add_rule(CaptureRule(id="r1", filter="~u example.com", action="include"))
    assert addon.delete_rule("r1") is True
    assert addon.delete_rule("r1") is False


def test_clear_rules() -> None:
    addon = CaptureAddon(FlowStore())
    addon.add_rule(CaptureRule(id="r1", filter="~u example.com", action="include"))
    assert addon.clear_rules() == 1
    assert len(addon.list_rules()) == 0


# ---------------------------------------------------------------------------
# Capture decision: no rules
# ---------------------------------------------------------------------------


def test_capture_all_by_default() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.response(_make_flow("http://example.com/"))
    assert store.count() == 1


def test_capture_filter_blocks() -> None:
    store = FlowStore()
    addon = CaptureAddon(store, capture_filter="~u example.com")
    addon.response(_make_flow("http://example.org/"))
    assert store.count() == 0


def test_capture_filter_allows() -> None:
    store = FlowStore()
    addon = CaptureAddon(store, capture_filter="~u example.com")
    addon.response(_make_flow("http://example.com/"))
    assert store.count() == 1


# ---------------------------------------------------------------------------
# Capture decision: include rules
# ---------------------------------------------------------------------------


def test_include_rule_limits_capture() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.add_rule(CaptureRule(id="r1", filter="~u api.example.com", action="include"))

    addon.response(_make_flow("http://example.com/"))
    addon.response(_make_flow("http://api.example.com/"))
    assert store.count() == 1
    assert store.list()[0][1].request.host == "api.example.com"


def test_multiple_include_rules_any_match() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.add_rule(CaptureRule(id="r1", filter="~u foo.com", action="include"))
    addon.add_rule(CaptureRule(id="r2", filter="~u bar.com", action="include"))

    addon.response(_make_flow("http://foo.com/"))
    addon.response(_make_flow("http://bar.com/"))
    addon.response(_make_flow("http://baz.com/"))
    assert store.count() == 2


# ---------------------------------------------------------------------------
# Capture decision: exclude rules
# ---------------------------------------------------------------------------


def test_exclude_rule_skips_capture() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.add_rule(CaptureRule(id="r1", filter="~t image/*", action="exclude"))

    flow = _make_flow("http://example.com/logo.png")
    flow.response = http.Response.make(200, b"", {"Content-Type": "image/png"})
    addon.response(flow)

    addon.response(_make_flow("http://example.com/api"))
    assert store.count() == 1
    assert store.list()[0][1].request.path == "/api"


# ---------------------------------------------------------------------------
# Capture decision: include + exclude
# ---------------------------------------------------------------------------


def test_exclude_overrides_include() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.add_rule(CaptureRule(id="inc", filter="~u example.com", action="include"))
    addon.add_rule(CaptureRule(id="exc", filter="~u example.com/health", action="exclude"))

    addon.response(_make_flow("http://example.com/api"))
    addon.response(_make_flow("http://example.com/health"))
    addon.response(_make_flow("http://other.com/"))
    assert store.count() == 1
    assert store.list()[0][1].request.path == "/api"


# ---------------------------------------------------------------------------
# Capture decision: disabled rule
# ---------------------------------------------------------------------------


def test_disabled_rule_ignored() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.add_rule(
        CaptureRule(id="r1", enabled=False, filter="~u example.com", action="include")
    )

    addon.response(_make_flow("http://example.com/"))
    # No enabled include rules -> capture all.
    assert store.count() == 1


# ---------------------------------------------------------------------------
# Capture decision: with base capture_filter
# ---------------------------------------------------------------------------


def test_rules_combined_with_capture_filter() -> None:
    store = FlowStore()
    addon = CaptureAddon(store, capture_filter="~u example.com")
    addon.add_rule(CaptureRule(id="r1", filter="~m POST", action="include"))

    addon.response(_make_flow("http://example.com/", method="GET"))
    addon.response(_make_flow("http://example.com/", method="POST"))
    addon.response(_make_flow("http://other.com/", method="POST"))
    assert store.count() == 1
    assert store.list()[0][1].request.method == "POST"


# ---------------------------------------------------------------------------
# Error flows
# ---------------------------------------------------------------------------


def test_error_flows_are_captured() -> None:
    store = FlowStore()
    addon = CaptureAddon(store)
    addon.add_rule(CaptureRule(id="r1", filter="~u example.com", action="include"))

    addon.error(_make_flow("http://example.com/"))
    addon.error(_make_flow("http://other.com/"))
    assert store.count() == 1
