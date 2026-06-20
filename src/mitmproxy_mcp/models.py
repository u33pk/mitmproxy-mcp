"""Pydantic models for serializing mitmproxy HTTPFlow objects."""

from __future__ import annotations

import base64
from typing import Any, Literal

from mitmproxy import http
from mitmproxy.websocket import WebSocketData, WebSocketMessage
from pydantic import BaseModel, Field

from mitmproxy_mcp.crypto import (
    APPLIED_HANDLERS_KEY,
    DECRYPTED_REQUEST_KEY,
    DECRYPTED_RESPONSE_KEY,
)


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
    decrypted_content: str | None = None
    decrypted_content_encoding: Literal["text", "base64"] = "text"
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
    decrypted_content: str | None = None
    decrypted_content_encoding: Literal["text", "base64"] = "text"
    timestamp_start: float
    timestamp_end: float


class WebSocketMessageModel(BaseModel):
    from_client: bool
    type: Literal["text", "binary"]
    content: str | None = None
    text: str | None = None
    content_encoding: Literal["text", "base64"] = "text"
    content_length: int = 0
    decrypted_content: str | None = None
    decrypted_text: str | None = None
    decrypted_content_encoding: Literal["text", "base64"] = "text"
    timestamp: float
    dropped: bool = False
    injected: bool = False


class WebSocketDataModel(BaseModel):
    messages: list[WebSocketMessageModel] = Field(default_factory=list)
    closed_by_client: bool | None = None
    close_code: int | None = None
    close_reason: str | None = None
    timestamp_end: float | None = None


class ProtocolInfoModel(BaseModel):
    request_http_version: str | None = None
    response_http_version: str | None = None
    client_alpn: str | None = None
    server_alpn: str | None = None
    client_tls_version: str | None = None
    server_tls_version: str | None = None
    client_sni: str | None = None
    server_sni: str | None = None


class FlowModel(BaseModel):
    id: str
    store_id: int
    request: RequestModel
    response: ResponseModel | None = None
    protocol: ProtocolInfoModel = Field(default_factory=ProtocolInfoModel)
    is_websocket: bool = False
    websocket: WebSocketDataModel | None = None
    client_address: list[str] | None = None
    server_address: list[str] | None = None
    comment: str | None = None
    marked: bool = False
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    crypto: dict[str, Any] = Field(default_factory=dict)


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


def _decode_alpn(alpn: bytes | None) -> str | None:
    """Decode ALPN bytes to string."""
    if alpn is None:
        return None
    return alpn.decode("ascii", errors="replace")


def headers_to_model(headers: http.Headers) -> list[Header]:
    return [Header(name=k, value=v) for k, v in headers.items()]


def headers_from_model(headers: list[Header]) -> http.Headers:
    return http.Headers([(h.name.encode(), h.value.encode()) for h in headers])


def request_to_model(req: http.Request, decrypted: bytes | None = None) -> RequestModel:
    content, encoding = _encode_content(req.raw_content)
    decrypted_content, decrypted_encoding = _encode_content(decrypted)
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
        decrypted_content=decrypted_content,
        decrypted_content_encoding=decrypted_encoding,
        timestamp_start=req.timestamp_start,
        timestamp_end=req.timestamp_end,
    )


def response_to_model(resp: http.Response, decrypted: bytes | None = None) -> ResponseModel:
    content, encoding = _encode_content(resp.raw_content)
    decrypted_content, decrypted_encoding = _encode_content(decrypted)
    return ResponseModel(
        http_version=resp.http_version,
        status_code=resp.status_code,
        reason=resp.reason,
        headers=headers_to_model(resp.headers),
        content=content,
        content_encoding=encoding,
        content_length=len(resp.raw_content) if resp.raw_content else 0,
        decrypted_content=decrypted_content,
        decrypted_content_encoding=decrypted_encoding,
        timestamp_start=resp.timestamp_start,
        timestamp_end=resp.timestamp_end,
    )


def websocket_message_to_model(
    msg: WebSocketMessage,
    max_content_size: int | None = None,
) -> WebSocketMessageModel:
    """Convert a mitmproxy WebSocketMessage to a Pydantic model."""
    raw = msg.content
    if msg.is_text:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        content = text
        content_encoding: Literal["text", "base64"] = "text"
    else:
        text = None
        content = base64.b64encode(raw).decode("ascii")
        content_encoding = "base64"

    decrypted_raw: bytes | None = None
    if getattr(msg, "metadata", None):
        decrypted_raw = msg.metadata.get(DECRYPTED_REQUEST_KEY)

    decrypted_content: str | None = None
    decrypted_text: str | None = None
    decrypted_encoding: Literal["text", "base64"] = "text"
    if decrypted_raw is not None:
        if msg.is_text:
            try:
                decrypted_text = decrypted_raw.decode("utf-8")
                decrypted_content = decrypted_text
            except UnicodeDecodeError:
                decrypted_text = decrypted_raw.decode("utf-8", errors="replace")
                decrypted_content = base64.b64encode(decrypted_raw).decode("ascii")
                decrypted_encoding = "base64"
        else:
            decrypted_content = base64.b64encode(decrypted_raw).decode("ascii")
            decrypted_encoding = "base64"

    truncated = False
    if max_content_size is not None and len(raw) > max_content_size:
        truncated = True
        if msg.is_text:
            content = content[:max_content_size] + "\n…(truncated)"
        else:
            # Re-encode truncated bytes to base64.
            content = base64.b64encode(raw[:max_content_size]).decode("ascii") + "\n…(truncated)"

    return WebSocketMessageModel(
        from_client=msg.from_client,
        type="text" if msg.is_text else "binary",
        content=content,
        text=text if not truncated else (text[:max_content_size] + "\n…(truncated)" if text else None),
        content_encoding=content_encoding,
        content_length=len(raw),
        decrypted_content=decrypted_content if not truncated else (
            (decrypted_content[:max_content_size] + "\n…(truncated)") if decrypted_content else None
        ),
        decrypted_text=decrypted_text if not truncated else (
            (decrypted_text[:max_content_size] + "\n…(truncated)") if decrypted_text else None
        ),
        decrypted_content_encoding=decrypted_encoding,
        timestamp=msg.timestamp,
        dropped=msg.dropped,
        injected=msg.injected,
    )


def websocket_to_model(
    ws: WebSocketData,
    max_content_size: int | None = None,
) -> WebSocketDataModel:
    """Convert mitmproxy WebSocketData to a Pydantic model."""
    return WebSocketDataModel(
        messages=[websocket_message_to_model(m, max_content_size=max_content_size) for m in ws.messages],
        closed_by_client=ws.closed_by_client,
        close_code=ws.close_code,
        close_reason=ws.close_reason,
        timestamp_end=ws.timestamp_end,
    )


def flow_to_model(
    flow: http.HTTPFlow,
    store_id: int | None = None,
    max_content_size: int | None = None,
) -> FlowModel:
    """Convert an mitmproxy HTTPFlow to a Pydantic FlowModel."""
    client_address: list[str] | None = None
    server_address: list[str] | None = None

    if flow.client_conn and flow.client_conn.peername:
        client_address = [str(flow.client_conn.peername[0]), str(flow.client_conn.peername[1])]
    if flow.server_conn and flow.server_conn.address:
        server_address = [str(flow.server_conn.address[0]), str(flow.server_conn.address[1])]

    is_websocket = flow.websocket is not None
    websocket_model = None
    if is_websocket:
        websocket_model = websocket_to_model(flow.websocket, max_content_size=max_content_size)

    protocol = ProtocolInfoModel(
        request_http_version=flow.request.http_version,
        response_http_version=flow.response.http_version if flow.response else None,
        client_alpn=_decode_alpn(flow.client_conn.alpn) if flow.client_conn else None,
        server_alpn=_decode_alpn(flow.server_conn.alpn) if flow.server_conn else None,
        client_tls_version=flow.client_conn.tls_version if flow.client_conn else None,
        server_tls_version=flow.server_conn.tls_version if flow.server_conn else None,
        client_sni=flow.client_conn.sni if flow.client_conn else None,
        server_sni=flow.server_conn.sni if flow.server_conn else None,
    )

    metadata = dict(flow.metadata) if flow.metadata else {}
    decrypted_request: bytes | None = metadata.get(DECRYPTED_REQUEST_KEY)
    decrypted_response: bytes | None = metadata.get(DECRYPTED_RESPONSE_KEY)
    applied_handlers: list[str] = metadata.get(APPLIED_HANDLERS_KEY, [])

    return FlowModel(
        id=flow.id,
        store_id=store_id if store_id is not None else -1,
        request=request_to_model(flow.request, decrypted=decrypted_request),
        response=response_to_model(flow.response, decrypted=decrypted_response) if flow.response else None,
        protocol=protocol,
        is_websocket=is_websocket,
        websocket=websocket_model,
        client_address=client_address,
        server_address=server_address,
        comment=flow.comment or None,
        marked=bool(flow.marked),
        tags=list(metadata.get("tags", [])),
        metadata=metadata,
        crypto={
            "applied_handlers": applied_handlers,
            "has_decrypted_request": decrypted_request is not None,
            "has_decrypted_response": decrypted_response is not None,
        },
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
