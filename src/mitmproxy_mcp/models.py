"""Pydantic models for serializing mitmproxy HTTPFlow objects."""

from __future__ import annotations

import base64
from typing import Literal

from mitmproxy import http
from pydantic import BaseModel, Field


class Header(BaseModel):
    name: str
    value: str


class RequestModel(BaseModel):
    method: str
    scheme: str
    host: str
    port: int
    path: str
    http_version: str
    headers: list[Header]
    content: str | None = None
    content_encoding: Literal["text", "base64"] = "text"
    content_length: int = 0
    timestamp_start: float
    timestamp_end: float


class ResponseModel(BaseModel):
    http_version: str
    status_code: int
    reason: str
    headers: list[Header]
    content: str | None = None
    content_encoding: Literal["text", "base64"] = "text"
    content_length: int = 0
    timestamp_start: float
    timestamp_end: float


class FlowModel(BaseModel):
    id: str
    request: RequestModel
    response: ResponseModel | None = None
    client_address: list[str] | None = None
    server_address: list[str] | None = None
    comment: str | None = None
    marked: bool = False
    tags: list[str] = Field(default_factory=list)


def _encode_content(data: bytes | None) -> tuple[str | None, Literal["text", "base64"]]:
    """Encode bytes as text or base64."""
    if data is None:
        return None, "text"
    try:
        return data.decode("utf-8"), "text"
    except UnicodeDecodeError:
        return base64.b64encode(data).decode("ascii"), "base64"


def _decode_content(content: str | None, encoding: Literal["text", "base64"]) -> bytes | None:
    """Decode text or base64 content back to bytes."""
    if content is None:
        return None
    if encoding == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8")


def headers_to_model(headers: http.Headers) -> list[Header]:
    return [Header(name=k, value=v) for k, v in headers.items()]


def headers_from_model(headers: list[Header]) -> http.Headers:
    return http.Headers([(h.name.encode(), h.value.encode()) for h in headers])


def request_to_model(req: http.Request) -> RequestModel:
    content, encoding = _encode_content(req.raw_content)
    return RequestModel(
        method=req.method,
        scheme=req.scheme,
        host=req.host,
        port=req.port,
        path=req.path,
        http_version=req.http_version,
        headers=headers_to_model(req.headers),
        content=content,
        content_encoding=encoding,
        content_length=len(req.raw_content) if req.raw_content else 0,
        timestamp_start=req.timestamp_start,
        timestamp_end=req.timestamp_end,
    )


def response_to_model(resp: http.Response) -> ResponseModel:
    content, encoding = _encode_content(resp.raw_content)
    return ResponseModel(
        http_version=resp.http_version,
        status_code=resp.status_code,
        reason=resp.reason,
        headers=headers_to_model(resp.headers),
        content=content,
        content_encoding=encoding,
        content_length=len(resp.raw_content) if resp.raw_content else 0,
        timestamp_start=resp.timestamp_start,
        timestamp_end=resp.timestamp_end,
    )


def flow_to_model(flow: http.HTTPFlow) -> FlowModel:
    """Convert an mitmproxy HTTPFlow to a Pydantic FlowModel."""
    client_address: list[str] | None = None
    server_address: list[str] | None = None

    if flow.client_conn and flow.client_conn.peername:
        client_address = [str(flow.client_conn.peername[0]), str(flow.client_conn.peername[1])]
    if flow.server_conn and flow.server_conn.address:
        server_address = [str(flow.server_conn.address[0]), str(flow.server_conn.address[1])]

    return FlowModel(
        id=flow.id,
        request=request_to_model(flow.request),
        response=response_to_model(flow.response) if flow.response else None,
        client_address=client_address,
        server_address=server_address,
        comment=flow.comment or None,
        marked=bool(flow.marked),
        tags=list(flow.metadata.get("tags", [])) if flow.metadata else [],
    )


def update_request_from_model(req: http.Request, model: RequestModel) -> None:
    """Apply a RequestModel onto an existing mitmproxy Request."""
    if model.method:
        req.method = model.method
    if model.path:
        req.path = model.path
    if model.headers:
        req.headers = headers_from_model(model.headers)
    if model.content is not None:
        req.content = _decode_content(model.content, model.content_encoding)
    # scheme/host/port changes would need reconstructing the URL; kept simple for now


def update_response_from_model(resp: http.Response, model: ResponseModel) -> None:
    """Apply a ResponseModel onto an existing mitmproxy Response."""
    if model.status_code:
        resp.status_code = model.status_code
    if model.reason:
        resp.reason = model.reason
    if model.headers:
        resp.headers = headers_from_model(model.headers)
    if model.content is not None:
        resp.content = _decode_content(model.content, model.content_encoding)


def request_from_model(model: RequestModel) -> http.Request:
    """Create a new mitmproxy Request from a RequestModel."""
    content = _decode_content(model.content, model.content_encoding)
    return http.Request.make(
        method=model.method,
        url=f"{model.scheme}://{model.host}:{model.port}{model.path}",
        content=content or b"",
        headers={h.name: h.value for h in model.headers} if model.headers else {},
    )
