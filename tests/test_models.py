"""Tests for mitmproxy_mcp.models."""

from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.models import (
    Header,
    flow_to_model,
    request_from_model,
    update_request_from_model,
)


def _make_flow() -> http.HTTPFlow:
    req = http.Request.make("GET", "http://example.com/path?a=1")
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=("example.com", 80))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def test_flow_to_model_request_only() -> None:
    flow = _make_flow()
    model = flow_to_model(flow)
    assert model.id == flow.id
    assert model.request.method == "GET"
    assert model.request.host == "example.com"
    assert model.request.path == "/path?a=1"
    assert model.response is None


def test_flow_to_model_with_response() -> None:
    flow = _make_flow()
    flow.response = http.Response.make(200, b"hello", {"X-Test": "yes"})
    model = flow_to_model(flow)
    assert model.response is not None
    assert model.response.status_code == 200
    assert model.response.content == "hello"


def test_update_request_from_model() -> None:
    flow = _make_flow()
    model = flow_to_model(flow)
    model.request.method = "POST"
    model.request.path = "/new"
    model.request.headers = [Header(name="X-Custom", value="1")]
    model.request.content = "body"
    model.request.content_encoding = "text"
    update_request_from_model(flow.request, model.request)
    assert flow.request.method == "POST"
    assert flow.request.path == "/new"
    assert flow.request.headers["X-Custom"] == "1"
    assert flow.request.content == b"body"


def test_request_from_model() -> None:
    req = http.Request.make("GET", "http://example.com/")
    model = flow_to_model(_make_flow()).request
    new_req = request_from_model(model)
    assert new_req.method == "GET"
    assert new_req.host == "example.com"


def test_flow_to_model_protocol_info() -> None:
    flow = _make_flow()
    flow.request.http_version = "HTTP/2"
    flow.response = http.Response.make(200, b"ok")
    flow.response.http_version = "HTTP/2"

    client = flow.client_conn
    client.alpn = b"h2"
    client.tls_version = "TLSv1.3"
    client.sni = "example.com"

    server = flow.server_conn
    server.alpn = b"h2"
    server.tls_version = "TLSv1.3"
    server.sni = "example.com"

    model = flow_to_model(flow)
    proto = model.protocol
    assert proto.request_http_version == "HTTP/2"
    assert proto.response_http_version == "HTTP/2"
    assert proto.client_alpn == "h2"
    assert proto.server_alpn == "h2"
    assert proto.client_tls_version == "TLSv1.3"
    assert proto.server_tls_version == "TLSv1.3"
    assert proto.client_sni == "example.com"
    assert proto.server_sni == "example.com"
