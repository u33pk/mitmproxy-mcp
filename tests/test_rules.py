"""Tests for mitmproxy_mcp.rules."""

import asyncio

import pytest
from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.rules import Action, Rule, RulesAddon


def _make_flow(
    url: str = "http://example.com/",
    method: str = "GET",
    content: bytes = b"",
) -> http.HTTPFlow:
    req = http.Request.make(method, url, content=content)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def _make_response(flow: http.HTTPFlow, status_code: int = 200) -> None:
    flow.response = http.Response.make(status_code, content=b"OK")


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Rule validation
# ---------------------------------------------------------------------------


def test_rule_invalid_filter() -> None:
    with pytest.raises(ValueError):
        Rule(
            id="r1",
            filter="~~~invalid",
            actions=[Action(type="kill")],
        )


def test_action_set_header_requires_fields() -> None:
    with pytest.raises(ValueError):
        Action(type="set_header", target="request")


def test_action_set_body_requires_content() -> None:
    with pytest.raises(ValueError):
        Action(type="set_body", target="request")


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------


def test_add_and_list_rules() -> None:
    addon = RulesAddon()
    rule = Rule(
        id="r1",
        name="test",
        filter="~u example.com",
        actions=[Action(type="kill")],
    )
    addon.add_rule(rule)
    assert len(addon.list_rules()) == 1
    assert addon.list_rules()[0].id == "r1"


def test_add_rule_replaces_same_id() -> None:
    addon = RulesAddon()
    addon.add_rule(Rule(id="r1", filter="~u example.com", actions=[Action(type="kill")]))
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.org",
            actions=[Action(type="intercept")],
        )
    )
    rules = addon.list_rules()
    assert len(rules) == 1
    assert rules[0].actions[0].type == "intercept"


def test_delete_rule() -> None:
    addon = RulesAddon()
    addon.add_rule(Rule(id="r1", filter="~u example.com", actions=[Action(type="kill")]))
    assert addon.delete_rule("r1") is True
    assert addon.delete_rule("r1") is False


def test_clear_rules() -> None:
    addon = RulesAddon()
    addon.add_rule(Rule(id="r1", filter="~u example.com", actions=[Action(type="kill")]))
    assert addon.clear_rules() == 1
    assert len(addon.list_rules()) == 0


# ---------------------------------------------------------------------------
# Request-phase actions
# ---------------------------------------------------------------------------


def test_set_header_request() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="set_header", target="request", name="X-Test", value="1")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert flow.request.headers["X-Test"] == "1"


def test_remove_header_request() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="remove_header", target="request", name="X-Remove")],
        )
    )
    flow = _make_flow("http://example.com/")
    flow.request.headers["X-Remove"] = "me"
    assert "X-Remove" in flow.request.headers
    _run(addon.request(flow))
    assert "X-Remove" not in flow.request.headers


def test_set_body_request() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="set_body", target="request", content="hello")],
        )
    )
    flow = _make_flow("http://example.com/", method="POST", content=b"old")
    _run(addon.request(flow))
    assert flow.request.content == b"hello"


def test_replace_body_request() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[
                Action(type="replace_body", target="request", pattern="old", replacement="new")
            ],
        )
    )
    flow = _make_flow("http://example.com/", method="POST", content=b"old data")
    _run(addon.request(flow))
    assert flow.request.content == b"new data"


def test_set_path() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="set_path", path="/modified")],
        )
    )
    flow = _make_flow("http://example.com/original")
    _run(addon.request(flow))
    assert flow.request.path == "/modified"


def test_set_method() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="set_method", method="POST")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert flow.request.method == "POST"


# ---------------------------------------------------------------------------
# Response-phase actions
# ---------------------------------------------------------------------------


def test_set_header_response() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="response",
            actions=[
                Action(type="set_header", target="response", name="X-Response", value="yes")
            ],
        )
    )
    flow = _make_flow("http://example.com/")
    _make_response(flow)
    _run(addon.response(flow))
    assert flow.response.headers["X-Response"] == "yes"


def test_set_status_creates_response() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="response",
            actions=[Action(type="set_status", status_code=418, reason="I'm a teapot")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.response(flow))
    assert flow.response is not None
    assert flow.response.status_code == 418
    assert flow.response.reason == "I'm a teapot"


def test_set_body_response_base64() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="response",
            actions=[Action(type="set_body", target="response", content="aGVsbG8=", encoding="base64")],
        )
    )
    flow = _make_flow("http://example.com/")
    _make_response(flow)
    _run(addon.response(flow))
    assert flow.response.content == b"hello"


# ---------------------------------------------------------------------------
# Control actions
# ---------------------------------------------------------------------------


def test_kill_action() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="kill")],
        )
    )
    flow = _make_flow("http://example.com/")
    flow.live = True
    _run(addon.request(flow))
    assert flow.error is not None
    assert not flow.live


def test_intercept_and_resume_actions() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="intercept"), Action(type="resume")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert not flow.intercepted


def test_delay_action() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="delay", seconds=0.01)],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    # No exception means success; delay is too short to assert precisely.


# ---------------------------------------------------------------------------
# Metadata actions
# ---------------------------------------------------------------------------


def test_mark_comment_tag_actions() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[
                Action(type="mark", marker="★"),
                Action(type="comment", comment="matched"),
                Action(type="tag", tags=["auto"]),
            ],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert flow.marked == "★"
    assert flow.comment == "matched"
    assert flow.metadata["tags"] == ["auto"]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_phase_filtering() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="response",
            actions=[Action(type="set_path", path="/should-not-run")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert flow.request.path == "/"


def test_disabled_rule_ignored() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            enabled=False,
            filter="~u example.com",
            phase="request",
            actions=[Action(type="set_path", path="/modified")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert flow.request.path == "/"


def test_rules_applied_metadata() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="r1",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="set_method", method="POST")],
        )
    )
    addon.add_rule(
        Rule(
            id="r2",
            filter="~u example.com",
            phase="request",
            actions=[Action(type="comment", comment="second")],
        )
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    applied = flow.metadata["mitmproxy_mcp_rules_applied"]
    assert "r1" in applied
    assert "r2" in applied
    assert flow.comment == "second"
