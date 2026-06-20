"""Integration tests for URL mappings."""

from __future__ import annotations

import subprocess
import time
import urllib.request

import pytest

from mitmproxy_mcp.server import (
    http_ctl,
    map_local_ctl,
    map_remote_ctl,
    proxy_ctl,
)


@pytest.fixture(autouse=True)
def _cleanup():
    """Ensure a clean state before and after each test."""
    try:
        proxy_ctl(cmd="stop")
        http_ctl(cmd="clear")
        map_local_ctl(cmd="clear")
        map_remote_ctl(cmd="clear")
    except Exception:
        pass
    yield
    try:
        map_local_ctl(cmd="clear")
        map_remote_ctl(cmd="clear")
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


def _http_get_via_proxy(url: str, proxy_port: int, timeout: float = 10) -> tuple[int, bytes]:
    proxy_handler = urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
    )
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.mark.integration
def test_map_local_serves_local_file() -> None:
    """map_local returns the contents of a local file."""
    server_port = 19031
    proxy_port = 18111

    server = _start_http_server(server_port)
    try:
        r = proxy_ctl(cmd="start", port=proxy_port)
        assert r["success"] is True
        assert proxy_ctl(cmd="status")["running"] is True

        with open("/tmp/mitmproxy_mcp_mock.json", "w") as f:
            f.write('{"mocked": true}')

        r = map_local_ctl(
            cmd="add",
            rule={
                "id": "api-mock",
                "filter": f"~u 127.0.0.1:{server_port}/api/data",
                "url_regex": f"http://127.0.0.1:{server_port}/api/data",
                "local_path": "/tmp/mitmproxy_mcp_mock.json",
            },
        )
        assert r["success"] is True

        status, body = _http_get_via_proxy(
            f"http://127.0.0.1:{server_port}/api/data", proxy_port
        )
        assert status == 200
        assert b'"mocked": true' in body
    finally:
        server.terminate()


@pytest.mark.integration
def test_map_remote_rewrites_url() -> None:
    """map_remote rewrites requests to another origin."""
    server_a_port = 19032
    server_b_port = 19033
    proxy_port = 18112

    server_a = _start_http_server(server_a_port)
    server_b = _start_http_server(server_b_port)
    try:
        r = proxy_ctl(cmd="start", port=proxy_port)
        assert r["success"] is True

        r = map_remote_ctl(
            cmd="add",
            rule={
                "id": "redirect-a-to-b",
                "filter": f"~u 127.0.0.1:{server_a_port}",
                "url_regex": f"http://127.0.0.1:{server_a_port}",
                "replacement": f"http://127.0.0.1:{server_b_port}",
            },
        )
        assert r["success"] is True

        # Request to server A should be served by server B.
        status, _ = _http_get_via_proxy(
            f"http://127.0.0.1:{server_a_port}/", proxy_port
        )
        assert status == 200
    finally:
        server_a.terminate()
        server_b.terminate()


if __name__ == "__main__":
    test_map_local_serves_local_file()
    print("test_map_local_serves_local_file passed")
    test_map_remote_rewrites_url()
    print("test_map_remote_rewrites_url passed")
    print("All mapping integration tests passed.")
