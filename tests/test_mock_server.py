"""Integration tests for mock server (server-side playback)."""

from __future__ import annotations

import subprocess
import time
import urllib.request

import pytest

from mitmproxy_mcp.server import (
    http_ctl,
    mock_server_ctl,
    proxy_ctl,
)


@pytest.fixture(autouse=True)
def _cleanup():
    """Ensure a clean state before and after each test."""
    try:
        proxy_ctl(cmd="stop")
        http_ctl(cmd="clear")
    except Exception:
        pass
    yield
    try:
        mock_server_ctl(cmd="stop")
        http_ctl(cmd="clear")
        proxy_ctl(cmd="stop")
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


def _http_get_via_proxy(url: str, proxy_port: int, timeout: float = 10) -> tuple[int, dict]:
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
def test_mock_server_returns_recorded_response() -> None:
    """Mock server returns a recorded response without contacting the origin."""
    server_port = 19021
    proxy_port = 18101

    server = _start_http_server(server_port)
    try:
        r = proxy_ctl(cmd="start", port=proxy_port)
        assert r["success"] is True
        assert proxy_ctl(cmd="status")["running"] is True

        # 1. Capture a real request.
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/", proxy_port)
        time.sleep(0.5)

        flows = http_ctl(cmd="list")["flows"]
        assert len(flows) == 1
        flow_id = flows[0]["store_id"]
        recorded_status = flows[0]["response"]["status_code"]

        # 2. Start mock server with the captured flow.
        r = mock_server_ctl(cmd="start", flow_ids=[flow_id])
        assert r["success"] is True
        assert mock_server_ctl(cmd="status")["mocked_flows"] == 1

        # 3. Stop the real server.
        server.terminate()
        server.wait()
        server = None

        # 4. Request the same URL again through the proxy.
        # The real server is down, but mock server should still return 200.
        status, _ = _http_get_via_proxy(
            f"http://127.0.0.1:{server_port}/", proxy_port
        )
        assert status == recorded_status == 200
    finally:
        if server is not None:
            server.terminate()


@pytest.mark.integration
def test_mock_server_stop() -> None:
    """Stopping the mock server clears recorded responses."""
    server_port = 19022
    proxy_port = 18102

    server = _start_http_server(server_port)
    try:
        proxy_ctl(cmd="start", port=proxy_port)
        _http_get_via_proxy(f"http://127.0.0.1:{server_port}/", proxy_port)
        time.sleep(0.5)

        flow_id = http_ctl(cmd="list")["flows"][0]["store_id"]
        mock_server_ctl(cmd="start", flow_ids=[flow_id])
        assert mock_server_ctl(cmd="status")["mocked_flows"] == 1

        r = mock_server_ctl(cmd="stop")
        assert r["success"] is True
        assert mock_server_ctl(cmd="status")["mocked_flows"] == 0
    finally:
        server.terminate()


if __name__ == "__main__":
    test_mock_server_returns_recorded_response()
    print("test_mock_server_returns_recorded_response passed")
    test_mock_server_stop()
    print("test_mock_server_stop passed")
    print("All mock server integration tests passed.")
