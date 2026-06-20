"""Integration test exercising every MCP tool end-to-end.

Run with:

    pytest tests/test_all_tools.py -m integration -v

Or directly:

    python tests/test_all_tools.py
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from mitmproxy_mcp.models import Header
from mitmproxy_mcp.server import (
    flow_action,
    http_ctl,
    proxy_ctl,
    store,
)


@pytest.mark.integration
def test_all_tools() -> None:
    """Call each tool and assert basic success/behavior."""
    # 1. proxy_status (not running)
    r = proxy_ctl(cmd="status")
    assert r["running"] is False

    # 2. proxy_list_options
    r = proxy_ctl(cmd="list_options")
    assert "listen_host" in r["options"]
    assert "mode" in r["options"]

    # 3. proxy_start
    r = proxy_ctl(cmd="start", port=18082)
    assert r["success"] is True

    # 3b. wireguard_config should fail in regular mode
    r = proxy_ctl(cmd="wireguard_config")
    assert r["success"] is False

    # 4. proxy_status (running)
    r = proxy_ctl(cmd="status")
    assert r["running"] is True

    # 5. flow_action create
    r = flow_action(
        action="create",
        method="GET",
        url="http://127.0.0.1:9999/test",
        headers=[Header(name="X-Test", value="1")],
        comment="created",
    )
    assert r["success"] is True
    fid = r["flow_id"]

    # 6. http_ctl get
    r = http_ctl(cmd="get", flow_id=fid)
    assert r["success"] is True
    assert r["flow"]["comment"] == "created"

    # 7. flow_action update
    r = flow_action(
        action="update",
        flow_id=fid,
        request_method="POST",
        request_path="/changed",
        response_status=201,
        comment="updated",
        marked=True,
    )
    assert r["success"] is True
    assert r["flow"]["comment"] == "updated"
    assert r["flow"]["marked"] is True
    assert r["flow"]["request"]["method"] == "POST"

    # 8. http_ctl extract_json and http_ctl get with preview
    json_fid = flow_action(
        action="create",
        method="POST",
        url="http://127.0.0.1:9999/api",
        headers=[Header(name="Content-Type", value="application/json")],
        body='{"users":[{"name":"Alice"},{"name":"Bob"}],"count":2}',
    )["flow_id"]
    r = http_ctl(
        cmd="extract_json",
        flow_id=json_fid,
        target="request",
        jsonpath=["$.users[*].name", "$.count"],
    )
    assert r["success"] is True
    assert r["extracted"]["$.users[*].name"] == ["Alice", "Bob"]
    assert r["extracted"]["$.count"] == 2

    r = http_ctl(cmd="get", flow_id=json_fid, max_content_size=20)
    assert r["success"] is True
    assert r["flow"]["request"]["content"] is None
    assert "content_preview" in r["flow"]["request"]

    # 9. http_ctl list
    r = http_ctl(cmd="list")
    assert r["total"] >= 2

    # 10. http_ctl save
    path = "/tmp/all_tools_test.mitm"
    if os.path.exists(path):
        os.remove(path)
    r = http_ctl(cmd="save", path=path)
    assert r["success"] is True
    assert os.path.exists(path)

    # 11. http_ctl clear
    r = http_ctl(cmd="clear")
    assert r["success"] is True
    assert http_ctl(cmd="list")["total"] == 0

    # 12. http_ctl load
    r = http_ctl(cmd="load", path=path)
    assert r["loaded"] >= 1

    # 13. flow_action send
    server = subprocess.Popen(
        ["python", "-m", "http.server", "19001", "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    try:
        r = flow_action(action="send", method="GET", url="http://127.0.0.1:19001/")
        assert r["success"] is True
        time.sleep(2)

        # 14. flow_action replay
        fid = store.list_ids()[0]
        r = flow_action(action="replay", flow_id=fid, use_modified=False)
        assert r["success"] is True
        time.sleep(2)

        # 15. http_ctl delete
        fid = store.list_ids()[0]
        r = http_ctl(cmd="delete", flow_id=fid)
        assert r["success"] is True
        assert http_ctl(cmd="get", flow_id=fid)["success"] is False
    finally:
        server.terminate()

    # 16. proxy_stop
    r = proxy_ctl(cmd="stop")
    assert r["success"] is True
    assert proxy_ctl(cmd="status")["running"] is False


if __name__ == "__main__":
    test_all_tools()
    print("All tools exercised successfully.")
