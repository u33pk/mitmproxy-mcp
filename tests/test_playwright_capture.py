"""Integration test: capture Playwright browser traffic with mitmproxy-mcp.

This test is skipped by default because it requires a network connection
and a Playwright browser installation. Run with:

    pytest tests/test_playwright_capture.py -v -m integration

Or run the script directly:

    python tests/test_playwright_capture.py
"""

from __future__ import annotations

import socket
import subprocess
import time

import pytest

playwright = pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

from mitmproxy_mcp.server import flows_clear, flows_list, proxy_start, proxy_stop


@pytest.mark.integration
def test_capture_http_local_server() -> None:
    """Verify Playwright HTTP traffic is captured through mitmproxy."""
    flows_clear()
    port = 18080
    result = proxy_start(port=port)
    assert result["success"] is True

    try:
        _wait_for_port("127.0.0.1", port, timeout=10)

        server = subprocess.Popen(
            ["python", "-m", "http.server", "19000", "--bind", "127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)

        with sync_playwright() as p:
            browser = p.chromium.launch(
                proxy={"server": f"http://127.0.0.1:{port}"},
                headless=True,
            )
            context = browser.new_context()
            page = context.new_page()
            page.goto("http://127.0.0.1:19000/", timeout=10000)
            page.close()
            context.close()
            browser.close()

        server.terminate()
        time.sleep(1)

        flows = flows_list()
        assert flows["total"] > 0
        req = flows["flows"][0]["request"]
        assert req["host"] == "127.0.0.1"
        assert req["port"] == 19000
    finally:
        proxy_stop()


@pytest.mark.integration
def test_capture_https_external_site() -> None:
    """Verify Playwright HTTPS traffic is captured through mitmproxy.

    We ignore certificate errors here so that mitmproxy's self-signed CA is
    accepted without installing it in the system/browser trust store.
    """
    flows_clear()
    port = 18081
    result = proxy_start(port=port)
    assert result["success"] is True

    try:
        _wait_for_port("127.0.0.1", port, timeout=10)

        with sync_playwright() as p:
            browser = p.chromium.launch(
                proxy={"server": f"http://127.0.0.1:{port}"},
                args=["--ignore-certificate-errors"],
                headless=True,
            )
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.goto("https://example.com", timeout=30000)
            page.close()
            context.close()
            browser.close()

        time.sleep(1)
        flows = flows_list()
        https_flows = [f for f in flows["flows"] if f["request"]["scheme"] == "https"]
        assert len(https_flows) > 0
    finally:
        proxy_stop()


def _wait_for_port(host: str, port: int, timeout: float = 10) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if sock.connect_ex((host, port)) == 0:
                return
        finally:
            sock.close()
        time.sleep(0.5)
    raise TimeoutError(f"Port {host}:{port} did not become available")


if __name__ == "__main__":
    print("Running HTTP local-server capture test...")
    test_capture_http_local_server()
    print("Running HTTPS external-site capture test...")
    test_capture_https_external_site()
    print("All Playwright capture tests passed.")
