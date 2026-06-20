"""Tests for user-defined crypto handlers and crypt_ctl."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from mitmproxy import http

from mitmproxy_mcp.crypto import (
    MODIFIED_REQUEST_KEY,
    CryptoAddon,
    CryptoHandler,
    CryptoResult,
    LoadedCryptoScript,
)
from mitmproxy_mcp.models import flow_to_model
from mitmproxy_mcp.server import crypt_ctl, flow_action
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.utils import create_http_flow


class XorHandler(CryptoHandler):
    id = "test-xor"
    name = "Test XOR"

    def __init__(self):
        super().__init__()
        self.key = b"\x20"  # flips lowercase <-> uppercase

    def _xor(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))

    def decrypt_request(self, flow: http.HTTPFlow) -> CryptoResult:
        return CryptoResult(body=self._xor(flow.request.raw_content or b""))

    def encrypt_request(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult:
        return CryptoResult(body=self._xor(plaintext))

    def decrypt_response(self, flow: http.HTTPFlow) -> CryptoResult | None:
        if flow.response is None:
            return None
        return CryptoResult(body=self._xor(flow.response.raw_content or b""))

    def encrypt_response(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult:
        return CryptoResult(body=self._xor(plaintext))


class DynamicKeyHandler(CryptoHandler):
    id = "test-dynamic-key"
    name = "Test dynamic key"

    def decrypt_response(self, flow: http.HTTPFlow) -> CryptoResult | None:
        if flow.response is None:
            return None
        if "/login" in flow.request.path:
            self.context["key"] = flow.response.raw_content or b""
            return CryptoResult(body=flow.response.raw_content)
        key = self.context.get("key", b"")
        raw = flow.response.raw_content or b""
        return CryptoResult(body=bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)))

    def decrypt_request(self, flow: http.HTTPFlow) -> CryptoResult | None:
        key = self.context.get("key", b"")
        if not key:
            return CryptoResult(error="key not ready")
        raw = flow.request.raw_content or b""
        return CryptoResult(body=bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)))

    def encrypt_request(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult:
        key = self.context.get("key", b"")
        return CryptoResult(body=bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext)))


class BrokenHandler(CryptoHandler):
    id = "test-broken"
    name = "Test broken"

    def decrypt_request(self, flow: http.HTTPFlow) -> CryptoResult:
        raise RuntimeError("boom")


def _make_request_flow(path: str = "/api", body: bytes = b"hello") -> http.HTTPFlow:
    flow = create_http_flow("POST", f"http://api.example.com{path}", body=body)
    flow.metadata = {}
    return flow


def _make_response_flow(body: bytes = b"world") -> http.HTTPFlow:
    flow = _make_request_flow()
    flow.response = http.Response.make(200, content=body)
    return flow


# ------------------------------------------------------------------------------
# CryptoAddon unit tests
# ------------------------------------------------------------------------------


def test_addon_load_and_list() -> None:
    store = FlowStore()
    addon = CryptoAddon(store)

    script = addon.load_script_from_handler(XorHandler())
    assert script.id == "test-xor"
    assert len(addon.list_scripts()) == 1

    addon.unload_script("test-xor")
    assert len(addon.list_scripts()) == 0


def test_simple_request_decryption() -> None:
    store = FlowStore()
    addon = CryptoAddon(store)
    addon.load_script_from_handler(XorHandler())

    flow = _make_request_flow(body=b"hello")
    addon.request(flow)

    assert flow.metadata["mitmproxy_mcp_decrypted_request"] == b"HELLO"
    model = flow_to_model(flow, store_id=1)
    assert model.request.decrypted_content == "HELLO"


def test_simple_response_decryption() -> None:
    store = FlowStore()
    addon = CryptoAddon(store)
    addon.load_script_from_handler(XorHandler())

    flow = _make_response_flow(body=b"world")
    addon.response(flow)

    assert flow.metadata["mitmproxy_mcp_decrypted_response"] == b"WORLD"
    model = flow_to_model(flow, store_id=1)
    assert model.response.decrypted_content == "WORLD"


def test_modified_request_is_re_encrypted() -> None:
    store = FlowStore()
    addon = CryptoAddon(store)
    addon.load_script_from_handler(XorHandler())

    flow = _make_request_flow(body=b"hello")
    # Simulate the user editing the decrypted plaintext.
    flow.metadata[MODIFIED_REQUEST_KEY] = b"WORLD"
    addon.request(flow)

    # The original request body should now be the encrypted modified plaintext.
    assert flow.request.raw_content == b"world"


def test_dynamic_key_from_response() -> None:
    store = FlowStore()
    addon = CryptoAddon(store)
    addon.load_script_from_handler(DynamicKeyHandler())

    # 1. Login response delivers the key.
    login = _make_request_flow("/login", b"")
    login.response = http.Response.make(200, content=b"mykey")
    addon.response(login)
    assert login.metadata["mitmproxy_mcp_decrypted_response"] == b"mykey"

    # 2. Later response is decrypted using that key.
    flow = _make_request_flow("/data", b"")
    cipher = bytes(b ^ b"mykey"[i % 5] for i, b in enumerate(b"secret"))
    flow.response = http.Response.make(200, content=cipher)
    addon.response(flow)
    assert flow.metadata["mitmproxy_mcp_decrypted_response"] == b"secret"

    # 3. Request encryption uses the same key.
    req = _make_request_flow("/data", b"")
    plain = b"hello"
    req.metadata[MODIFIED_REQUEST_KEY] = plain
    addon.request(req)
    expected = bytes(b ^ b"mykey"[i % 5] for i, b in enumerate(plain))
    assert req.request.raw_content == expected


def test_broken_handler_does_not_crash() -> None:
    store = FlowStore()
    addon = CryptoAddon(store)
    script = addon.load_script_from_handler(BrokenHandler())

    flow = _make_request_flow(body=b"hello")
    addon.request(flow)

    assert script.error_count == 1
    assert script.last_error is not None
    assert "boom" in script.last_error


# ------------------------------------------------------------------------------
# Tool-level tests
# ------------------------------------------------------------------------------


def _write_script(code: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        return f.name


def test_crypt_ctl_load_and_status() -> None:
    code = '''
from mitmproxy_mcp.crypto import CryptoHandler, CryptoResult

class Demo(CryptoHandler):
    id = "demo"
    def decrypt_request(self, flow):
        return CryptoResult(body=flow.request.raw_content)
'''
    path = _write_script(code)
    r = crypt_ctl(cmd="load", script_path=path)
    assert r["success"] is True
    assert r["script"]["id"] == "demo"

    r = crypt_ctl(cmd="status", script_id="demo")
    assert r["success"] is True
    assert r["script"]["error_count"] == 0

    r = crypt_ctl(cmd="unload", script_id="demo")
    assert r["success"] is True


def test_crypt_ctl_list_and_reload() -> None:
    code = '''
from mitmproxy_mcp.crypto import CryptoHandler

class Demo(CryptoHandler):
    id = "demo2"
'''
    path = _write_script(code)
    crypt_ctl(cmd="load", script_path=path)

    r = crypt_ctl(cmd="list")
    assert r["success"] is True
    assert any(s["id"] == "demo2" for s in r["scripts"])

    r = crypt_ctl(cmd="reload", script_id="demo2")
    assert r["success"] is True

    crypt_ctl(cmd="unload", script_id="demo2")


def test_flow_action_update_decrypted_body() -> None:
    from mitmproxy_mcp.server import store as global_store

    flow = _make_request_flow(body=b"hello")
    global_store.clear()
    global_store.add(flow)
    store_id = flow.metadata["mitmproxy_mcp_id"]

    # flow_action writes the modified decrypted body into metadata.
    r = flow_action(
        action="update",
        flow_id=store_id,
        decrypted_request_body="HELLO",
    )
    assert r["success"] is True
    assert flow.metadata[MODIFIED_REQUEST_KEY] == b"HELLO"


# ------------------------------------------------------------------------------
# Helper used only in tests
# ------------------------------------------------------------------------------


def _load_script_from_handler(self: CryptoAddon, handler: CryptoHandler) -> LoadedCryptoScript:
    """Test helper to load a handler instance directly without a file."""
    store = self._ensure_store()
    handler.on_load(store)
    script = LoadedCryptoScript(
        id=handler.id,
        name=handler.name or handler.id,
        path="<test>",
        handler=handler,
        loaded_at=__import__("time").time(),
    )
    with self._lock:
        self._scripts = [s for s in self._scripts if s.id != handler.id]
        self._scripts.append(script)
        self._scripts.sort(key=lambda s: s.handler.priority, reverse=True)
    return script


CryptoAddon.load_script_from_handler = _load_script_from_handler  # type: ignore[method-assign]
