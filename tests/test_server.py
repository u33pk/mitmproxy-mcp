"""Tests for mitmproxy_mcp.server tools that do not require a running proxy."""

from mitmproxy_mcp.server import proxy_ctl


def test_proxy_list_options() -> None:
    r = proxy_ctl(cmd="list_options")
    assert "options" in r
    opts = r["options"]
    assert "listen_host" in opts
    assert "listen_port" in opts
    assert "mode" in opts
    assert "ssl_insecure" in opts
    assert "tcp_hosts" in opts
    assert "udp_hosts" in opts


def test_wireguard_config_when_not_running() -> None:
    r = proxy_ctl(cmd="wireguard_config")
    assert r["success"] is False
    assert "WireGuard" in r["error"] or "WireGuard mode" in r["error"]
