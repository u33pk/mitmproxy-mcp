"""Tests for ProxyManager functionality.

Run integration tests with:

    pytest tests/test_proxy.py -m integration -v
"""

from __future__ import annotations

import pytest

from mitmproxy_mcp.proxy import ProxyManager
from mitmproxy_mcp.server import proxy_ctl, proxy_manager
from mitmproxy_mcp.store import FlowStore


def _ensure_stopped() -> None:
    """Stop the global proxy if it is running."""
    if proxy_manager.is_running:
        proxy_manager.stop()


def test_proxy_manager_web_properties_without_running() -> None:
    """Web UI properties should return sane defaults when proxy is not running."""
    manager = ProxyManager(FlowStore())
    assert manager.webui is False
    assert manager.web_port is None
    assert manager.web_url is None


@pytest.mark.integration
def test_proxy_start_with_webui() -> None:
    """Starting with webui=True should launch WebMaster and report web_url."""
    _ensure_stopped()
    proxy_port = 18090
    web_port = 18091

    try:
        r = proxy_ctl(
            cmd="start",
            port=proxy_port,
            webui=True,
            web_port=web_port,
        )
        assert r["success"] is True
        assert r["webui"] is True
        assert r["web_port"] == web_port
        assert r["web_url"].startswith(f"http://127.0.0.1:{web_port}")

        status = proxy_ctl(cmd="status")
        assert status["running"] is True
        assert status["webui"] is True
        assert status["web_port"] == web_port
        assert status["web_url"].startswith(f"http://127.0.0.1:{web_port}")

        # The underlying master should be a WebMaster instance.
        from mitmproxy.tools.web.master import WebMaster

        assert isinstance(proxy_manager._master, WebMaster)
    finally:
        _ensure_stopped()


@pytest.mark.integration
def test_proxy_start_without_webui() -> None:
    """Default start should use DumpMaster and not expose web UI fields."""
    _ensure_stopped()
    proxy_port = 18092

    try:
        r = proxy_ctl(cmd="start", port=proxy_port)
        assert r["success"] is True
        assert r["webui"] is False
        assert "web_port" not in r
        assert "web_url" not in r

        status = proxy_ctl(cmd="status")
        assert status["running"] is True
        assert status["webui"] is False
        assert "web_port" not in status
        assert "web_url" not in status

        from mitmproxy.tools.dump import DumpMaster

        assert isinstance(proxy_manager._master, DumpMaster)
    finally:
        _ensure_stopped()
