"""Integration tests for automatic rules and capture rules.

Run with:

    pytest tests/test_rules_integration.py -m integration -v

Or directly:

    python tests/test_rules_integration.py
"""

from __future__ import annotations

import http.client
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from mitmproxy_mcp.server import (
    capture_rule_add,
    capture_rule_delete,
    capture_rules_clear,
    capture_rules_list,
    flows_clear,
    flows_list,
    proxy_start,
    proxy_status,
    proxy_stop,
    rule_add,
    rules_clear,
)
from mitmproxy_mcp.proxy import CaptureRule
from mitmproxy_mcp.rules import Action, Rule


@pytest.fixture(autouse=True)
def _cleanup():
    """Ensure a clean state before and after each test."""
    try:
        proxy_stop()
        rules_clear()
        capture_rules_clear()
        flows_clear()
    except Exception:
        pass
    yield
    try:
        rules_clear()
        capture_rules_clear()
        flows_clear()
        proxy_stop()
    except Exception:
        pass


def _start_http_server(port: int) -> subprocess.Popen:
    server = subprocess.Popen(
        ["python", "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    return server


def _get_header(flow: dict, name: str) -> str | None:
    """Look up a header value in a serialized flow's header list."""
    for h in flow["response"]["headers"]:
        if h["name"].lower() == name.lower():
            return h["value"]
    return None


def _http_get_via_proxy(url: str, proxy_port: int, timeout: float = 10) -> tuple[int, dict]:
    """Send a GET through the proxy and return status + headers.

    HTTP errors (e.g. 404 from the origin) are returned instead of raised.
    Connection-level errors are raised so callers can assert on them.
    """
    proxy_handler = urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
    )
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


@pytest.mark.integration
def test_automatic_rule_modifies_response() -> None:
    """An automatic rule modifies response headers for matching flows."""
    server_port = 19011
    proxy_port = 18091

    server = _start_http_server(server_port)
    try:
        r = proxy_start(port=proxy_port)
        assert r["success"] is True
        assert proxy_status()["running"] is True

        r = rule_add(
            Rule(
                id="modify-api",
                filter=f"~u 127.0.0.1:{server_port}/api",
                phase="response",
                actions=[
                    Action(
                        type="set_header",
                        target="response",
                        name="X-Modified",
                        value="true",
                    )
                ],
            )
        )
        assert r["success"] is True

        # Request that matches the rule (returns 404 from origin, but rule still runs).
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/api", proxy_port)

        # Request that does not match.
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/other", proxy_port)

        time.sleep(1)

        flows = flows_list()["flows"]
        api_flows = [f for f in flows if f["request"]["path"] == "/api"]
        other_flows = [f for f in flows if f["request"]["path"] == "/other"]

        assert len(api_flows) == 1
        assert _get_header(api_flows[0], "x-modified") == "true"
        assert "modify-api" in api_flows[0]["metadata"].get(
            "mitmproxy_mcp_rules_applied", []
        )

        assert len(other_flows) == 1
        assert _get_header(other_flows[0], "x-modified") is None
    finally:
        server.terminate()


@pytest.mark.integration
def test_automatic_rule_blocks_request() -> None:
    """An automatic rule kills matching requests before they reach the server."""
    server_port = 19012
    proxy_port = 18092

    server = _start_http_server(server_port)
    try:
        r = proxy_start(port=proxy_port)
        assert r["success"] is True

        r = rule_add(
            Rule(
                id="block-health",
                filter=f"~u 127.0.0.1:{server_port}/health",
                phase="request",
                actions=[Action(type="kill")],
            )
        )
        assert r["success"] is True

        # Blocked request should fail at the client level.
        with pytest.raises((urllib.error.URLError, ConnectionError, http.client.RemoteDisconnected)):
            _http_get_via_proxy(f"http://127.0.0.1:{server_port}/health", proxy_port)

        # Normal request should succeed (directory listing from http.server).
        status, _ = _http_get_via_proxy(
            f"http://127.0.0.1:{server_port}/", proxy_port
        )
        assert status == 200

        time.sleep(1)
        flows = flows_list()["flows"]
        root_flows = [f for f in flows if f["request"]["path"] == "/"]
        assert len(root_flows) >= 1
        assert root_flows[0]["response"]["status_code"] == 200
    finally:
        server.terminate()


@pytest.mark.integration
def test_capture_rules_include_exclude() -> None:
    """Capture rules decide which flows are stored."""
    server_port = 19013
    proxy_port = 18093

    server = _start_http_server(server_port)
    try:
        r = proxy_start(port=proxy_port)
        assert r["success"] is True

        r = capture_rule_add(
            CaptureRule(
                id="include-api",
                filter=f"~u 127.0.0.1:{server_port}/api",
                action="include",
            )
        )
        assert r["success"] is True

        r = capture_rule_add(
            CaptureRule(
                id="exclude-internal",
                filter=f"~u 127.0.0.1:{server_port}/api/internal",
                action="exclude",
            )
        )
        assert r["success"] is True

        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/api/users", proxy_port)
        _http_get_via_proxy(
            f"http://127.0.0.1:{server_port}/api/internal", proxy_port
        )
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/other", proxy_port)

        time.sleep(1)

        flows = flows_list()["flows"]
        paths = {f["request"]["path"] for f in flows}

        assert "/api/users" in paths
        assert "/api/internal" not in paths
        assert "/other" not in paths
    finally:
        server.terminate()


@pytest.mark.integration
def test_capture_rules_runtime_update() -> None:
    """Capture rules can be changed at runtime without restarting proxy."""
    server_port = 19014
    proxy_port = 18094

    server = _start_http_server(server_port)
    try:
        r = proxy_start(port=proxy_port)
        assert r["success"] is True

        # First capture everything by adding no rules.
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/page1", proxy_port)
        time.sleep(0.5)
        assert flows_list()["total"] == 1

        # Add an include rule that only captures /api.
        capture_rule_add(
            CaptureRule(
                id="api-only",
                filter=f"~u 127.0.0.1:{server_port}/api",
                action="include",
            )
        )

        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/page2", proxy_port)
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/api/data", proxy_port)
        time.sleep(0.5)

        flows = flows_list()["flows"]
        paths = {f["request"]["path"] for f in flows}
        assert "/page1" in paths
        assert "/page2" not in paths
        assert "/api/data" in paths

        # Delete the rule and verify capture returns to all.
        capture_rule_delete("api-only")
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/page3", proxy_port)
        time.sleep(0.5)

        flows = flows_list()["flows"]
        paths = {f["request"]["path"] for f in flows}
        assert "/page3" in paths
    finally:
        server.terminate()


if __name__ == "__main__":
    test_automatic_rule_modifies_response()
    print("test_automatic_rule_modifies_response passed")
    test_automatic_rule_blocks_request()
    print("test_automatic_rule_blocks_request passed")
    test_capture_rules_include_exclude()
    print("test_capture_rules_include_exclude passed")
    test_capture_rules_runtime_update()
    print("test_capture_rules_runtime_update passed")
    print("All rule integration tests passed.")
