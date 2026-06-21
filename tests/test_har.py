"""Tests for HAR import/export."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from mitmproxy import http

from mitmproxy_mcp.har import har_to_flows, load_har, save_har
from mitmproxy_mcp.server import http_ctl, store
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.utils import create_http_flow


def _add_response(flow: http.HTTPFlow, status: int = 200, body: bytes = b"ok") -> None:
    flow.response = http.Response.make(status, content=body)


def test_roundtrip_text_request() -> None:
    store = FlowStore()
    flow = create_http_flow("GET", "https://example.com/api/users")
    _add_response(flow, 200, b'{"users":[]}')
    flow.comment = "test comment"
    store.add(flow)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
        path = f.name

    try:
        count = store.save_har(path)
        assert count == 1

        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert data["log"]["version"] == "1.2"
        assert len(data["log"]["entries"]) == 1
        entry = data["log"]["entries"][0]
        assert entry["request"]["method"] == "GET"
        assert entry["request"]["url"] == "https://example.com/api/users"
        assert entry["response"]["status"] == 200
        assert entry["comment"] == "test comment"

        imported = FlowStore()
        imported.load_har(path)
        assert imported.count() == 1
        loaded = imported.list_flows()[0]
        assert loaded.request.method == "GET"
        assert loaded.request.url == "https://example.com/api/users"
        assert loaded.response is not None
        assert loaded.response.status_code == 200
        assert loaded.response.content == b'{"users":[]}'
        assert loaded.comment == "test comment"
    finally:
        Path(path).unlink(missing_ok=True)


def test_roundtrip_binary_response() -> None:
    store = FlowStore()
    flow = create_http_flow("GET", "https://example.com/image.png")
    binary = bytes(range(256))
    _add_response(flow, 200, binary)
    store.add(flow)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
        path = f.name

    try:
        store.save_har(path)
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        content = data["log"]["entries"][0]["response"]["content"]
        assert content.get("encoding") == "base64"

        imported = FlowStore()
        imported.load_har(path)
        loaded = imported.list_flows()[0]
        assert loaded.response is not None
        assert loaded.response.content == binary
    finally:
        Path(path).unlink(missing_ok=True)


def test_roundtrip_post_json() -> None:
    store = FlowStore()
    body = b'{"name":"alice"}'
    flow = create_http_flow(
        "POST",
        "https://example.com/api/users",
        headers={"Content-Type": "application/json"},
        body=body,
    )
    _add_response(flow, 201, b'{"id":42}')
    store.add(flow)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
        path = f.name

    try:
        store.save_har(path)
        imported = FlowStore()
        imported.load_har(path)
        loaded = imported.list_flows()[0]
        assert loaded.request.method == "POST"
        assert loaded.request.content == body
        assert loaded.request.headers.get("Content-Type") == "application/json"
        assert loaded.response is not None
        assert loaded.response.status_code == 201
        assert loaded.response.content == b'{"id":42}'
    finally:
        Path(path).unlink(missing_ok=True)


def test_export_selected_flows() -> None:
    store = FlowStore()
    f1 = create_http_flow("GET", "https://example.com/one")
    f2 = create_http_flow("GET", "https://example.com/two")
    _add_response(f1)
    _add_response(f2)
    id1 = store.add(f1)
    store.add(f2)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
        path = f.name

    try:
        count = store.save_har(path, flow_ids=[id1])
        assert count == 1
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert len(data["log"]["entries"]) == 1
        assert data["log"]["entries"][0]["request"]["url"] == "https://example.com/one"
    finally:
        Path(path).unlink(missing_ok=True)


def test_import_invalid_entry_skipped() -> None:
    har_doc = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/valid",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "queryString": [],
                        "cookies": [],
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "cookies": [],
                        "content": {"size": 0, "mimeType": "text/plain"},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "not-a-url",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                    },
                },
            ],
        }
    }
    flows = har_to_flows(har_doc)
    assert len(flows) == 1
    assert flows[0].request.url == "https://example.com/valid"


def test_http_ctl_export_import() -> None:
    store.clear()
    flow = create_http_flow("GET", "https://example.com/api", body=b"q")
    _add_response(flow, 200, b"data")
    store.add(flow)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
        path = f.name

    try:
        result = http_ctl(cmd="export_har", path=path)
        assert result["success"] is True
        assert result["saved"] == 1

        store.clear()
        result = http_ctl(cmd="import_har", path=path)
        assert result["success"] is True
        assert result["loaded"] == 1
        assert store.count() == 1
        loaded = store.list_flows()[0]
        assert loaded.request.url == "https://example.com/api"
        assert loaded.response is not None
        assert loaded.response.content == b"data"
    finally:
        Path(path).unlink(missing_ok=True)


def test_har_content_size_matches() -> None:
    store = FlowStore()
    flow = create_http_flow("POST", "https://example.com/upload", body=b"hello")
    _add_response(flow, 200, b"world")
    store.add(flow)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
        path = f.name

    try:
        store.save_har(path)
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entry = data["log"]["entries"][0]
        assert entry["request"]["bodySize"] == 5
        assert entry["response"]["bodySize"] == 5
        assert entry["response"]["content"]["size"] == 5
    finally:
        Path(path).unlink(missing_ok=True)
