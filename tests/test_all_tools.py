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
    flow_create,
    flow_delete,
    flow_extract_json,
    flow_get,
    flow_replay,
    flow_update,
    flows_clear,
    flows_list,
    flows_load,
    flows_save,
    proxy_list_options,
    proxy_start,
    proxy_status,
    proxy_stop,
    request_send,
    store,
)


@pytest.mark.integration
def test_all_tools() -> None:
    """Call each tool and assert basic success/behavior."""
    # 1. proxy_status (not running)
    r = proxy_status()
    assert r["running"] is False

    # 2. proxy_list_options
    r = proxy_list_options()
    assert "listen_host" in r["options"]
    assert "mode" in r["options"]

    # 3. proxy_start
    r = proxy_start(port=18082)
    assert r["success"] is True

    # 4. proxy_status (running)
    r = proxy_status()
    assert r["running"] is True

    # 5. flow_create
    r = flow_create(
        "GET",
        "http://127.0.0.1:9999/test",
        headers=[Header(name="X-Test", value="1")],
        comment="created",
    )
    assert r["success"] is True
    fid = r["flow_id"]

    # 6. flow_get
    r = flow_get(fid)
    assert r["success"] is True
    assert r["flow"]["comment"] == "created"

    # 7. flow_update
    r = flow_update(
        fid,
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

    # 8. flow_extract_json and flow_get with preview
    json_fid = flow_create(
        "POST",
        "http://127.0.0.1:9999/api",
        headers=[Header(name="Content-Type", value="application/json")],
        body='{"users":[{"name":"Alice"},{"name":"Bob"}],"count":2}',
    )["flow_id"]
    r = flow_extract_json(
        json_fid,
        content_type="request",
        json_paths=["$.users[*].name", "$.count"],
    )
    assert r["success"] is True
    assert r["extracted"]["$.users[*].name"] == ["Alice", "Bob"]
    assert r["extracted"]["$.count"] == 2

    r = flow_get(json_fid, max_content_size=20)
    assert r["success"] is True
    assert r["flow"]["request"]["content"] is None
    assert "content_preview" in r["flow"]["request"]

    # 9. flows_list
    r = flows_list()
    assert r["total"] >= 2

    # 10. flows_save
    path = "/tmp/all_tools_test.mitm"
    if os.path.exists(path):
        os.remove(path)
    r = flows_save(path)
    assert r["success"] is True
    assert os.path.exists(path)

    # 11. flows_clear
    r = flows_clear()
    assert r["success"] is True
    assert flows_list()["total"] == 0

    # 12. flows_load
    r = flows_load(path)
    assert r["loaded"] >= 1

    # 13. request_send
    server = subprocess.Popen(
        ["python", "-m", "http.server", "19001", "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    try:
        r = request_send("GET", "http://127.0.0.1:19001/")
        assert r["success"] is True
        time.sleep(2)

        # 14. flow_replay
        fid = store.list_ids()[0]
        r = flow_replay(fid, use_modified=False)
        assert r["success"] is True
        time.sleep(2)

        # 15. flow_delete
        fid = store.list_ids()[0]
        r = flow_delete(fid)
        assert r["success"] is True
        assert flow_get(fid)["success"] is False
    finally:
        server.terminate()

    # 16. proxy_stop
    r = proxy_stop()
    assert r["success"] is True
    assert proxy_status()["running"] is False


if __name__ == "__main__":
    test_all_tools()
    print("All tools exercised successfully.")
