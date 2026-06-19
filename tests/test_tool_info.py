"""Tests for the progressive tool_info helper."""

from mitmproxy_mcp.tool_info import get_tool_info


def test_tool_info_returns_full_doc() -> None:
    r = get_tool_info("proxy_ctl")
    assert r["success"] is True
    assert r["tool"] == "proxy_ctl"
    assert "commands" in r["doc"]
    assert "start" in r["doc"]["commands"]


def test_tool_info_returns_command_doc() -> None:
    r = get_tool_info("flow_ctl", cmd="get")
    assert r["success"] is True
    assert r["tool"] == "flow_ctl"
    assert r["cmd"] == "get"
    assert "flow_id" in r["doc"]["required"]


def test_tool_info_unknown_tool() -> None:
    r = get_tool_info("not_a_tool")
    assert r["success"] is False
    assert "Unknown tool" in r["error"]


def test_tool_info_unknown_command() -> None:
    r = get_tool_info("proxy_ctl", cmd="boom")
    assert r["success"] is False
    assert "available_commands" in r
    assert "start" in r["available_commands"]
