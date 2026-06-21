"""HAR (HTTP Archive) import/export for mitmproxy HTTPFlow objects."""

from __future__ import annotations

import base64
import json
import logging
import mimetypes
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from mitmproxy import http
from mitmproxy.connection import Client, Server

logger = logging.getLogger(__name__)

HAR_VERSION = "1.2"


def _iso_timestamp(ts: float | None) -> str:
    """Convert a Unix timestamp to HAR ISO 8601 UTC string."""
    if ts is None:
        ts = 0.0
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_iso_timestamp(value: str | None) -> float:
    """Parse an ISO 8601 timestamp; return 0.0 if unparseable."""
    if not value:
        return 0.0
    try:
        # Python 3.11+ supports 'Z' directly.
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        logger.warning(f"Failed to parse HAR timestamp: {value}")
        return 0.0


def _encode_content_har(data: bytes | None) -> dict[str, Any]:
    """Encode body bytes for HAR content object."""
    if data is None:
        return {"size": 0, "mimeType": "text/plain"}

    size = len(data)
    mime_type = "application/octet-stream"
    try:
        text = data.decode("utf-8")
        return {"size": size, "mimeType": "text/plain", "text": text}
    except UnicodeDecodeError:
        return {
            "size": size,
            "mimeType": mime_type,
            "text": base64.b64encode(data).decode("ascii"),
            "encoding": "base64",
        }


def _decode_content_har(content: dict[str, Any] | None) -> bytes:
    """Decode HAR content object back to bytes."""
    if content is None:
        return b""
    text = content.get("text")
    if text is None:
        return b""
    if content.get("encoding") == "base64":
        return base64.b64decode(text)
    if isinstance(text, bytes):
        return text
    return text.encode("utf-8")


def _headers_to_har(headers: http.Headers) -> list[dict[str, str]]:
    return [{"name": k, "value": v} for k, v in headers.items()]


def _headers_from_har(entries: list[dict[str, Any]] | None) -> dict[str, str]:
    if not entries:
        return {}
    return {str(e["name"]): str(e["value"]) for e in entries}


def _parse_cookie_header(value: str) -> list[dict[str, str]]:
    """Parse a simple Cookie header into HAR cookie objects."""
    cookies: list[dict[str, str]] = []
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, cookie_value = part.partition("=")
            cookies.append({"name": name.strip(), "value": cookie_value.strip()})
    return cookies


def _parse_set_cookie_header(value: str) -> dict[str, Any]:
    """Parse a Set-Cookie header into a HAR cookie object (attributes ignored)."""
    first, _, _ = value.partition(";")
    name, _, cookie_value = first.partition("=")
    return {"name": name.strip(), "value": cookie_value.strip(), "httpOnly": "httponly" in value.lower()}


def _cookies_to_har(headers: http.Headers, is_response: bool) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    if is_response:
        for value in headers.get_all("set-cookie"):
            cookies.append(_parse_set_cookie_header(value))
    else:
        cookie_header = headers.get("cookie")
        if cookie_header:
            cookies.extend(_parse_cookie_header(cookie_header))
    return cookies


def _query_to_har(url: str) -> list[dict[str, str]]:
    parsed = urlparse(url)
    return [{"name": k, "value": v} for k, v in parse_qsl(parsed.query)]


def _post_data_to_har(req: http.Request) -> dict[str, Any] | None:
    data = req.raw_content
    if not data:
        return None

    content_type = req.headers.get("Content-Type", "application/octet-stream")
    mime_type = content_type.split(";")[0].strip()

    # Simple form data: try to produce params array.
    if mime_type == "application/x-www-form-urlencoded":
        try:
            params = [{"name": k, "value": v} for k, v in parse_qsl(data.decode("utf-8"))]
            return {"mimeType": content_type, "params": params}
        except UnicodeDecodeError:
            pass

    encoded = _encode_content_har(data)
    return {
        "mimeType": content_type,
        "text": encoded.get("text"),
        "encoding": encoded.get("encoding"),
    }


def _request_to_har(req: http.Request) -> dict[str, Any]:
    url = req.url or f"{req.scheme}://{req.host}:{req.port}{req.path}"
    return {
        "method": req.method,
        "url": url,
        "httpVersion": req.http_version or "HTTP/1.1",
        "headers": _headers_to_har(req.headers),
        "queryString": _query_to_har(url),
        "cookies": _cookies_to_har(req.headers, is_response=False),
        "headersSize": -1,
        "bodySize": len(req.raw_content) if req.raw_content else 0,
        "postData": _post_data_to_har(req),
    }


def _response_to_har(resp: http.Response, req_url: str) -> dict[str, Any]:
    content = _encode_content_har(resp.raw_content)
    redirect_url = ""
    location = resp.headers.get("location")
    if location:
        redirect_url = location

    return {
        "status": resp.status_code,
        "statusText": resp.reason or "",
        "httpVersion": resp.http_version or "HTTP/1.1",
        "headers": _headers_to_har(resp.headers),
        "cookies": _cookies_to_har(resp.headers, is_response=True),
        "content": content,
        "redirectURL": redirect_url,
        "headersSize": -1,
        "bodySize": len(resp.raw_content) if resp.raw_content else 0,
    }


def _flow_to_har_entry(flow: http.HTTPFlow, pageref: str = "page_1") -> dict[str, Any] | None:
    if flow.request is None:
        return None

    started = flow.request.timestamp_start
    ended = flow.response.timestamp_end if flow.response else flow.request.timestamp_end
    if ended is None:
        ended = started
    time_ms = max(0.0, ((ended or 0.0) - (started or 0.0)) * 1000)

    server_ip: str | None = None
    if flow.server_conn and flow.server_conn.peername:
        server_ip = str(flow.server_conn.peername[0])

    entry: dict[str, Any] = {
        "pageref": pageref,
        "startedDateTime": _iso_timestamp(started),
        "time": round(time_ms, 3),
        "request": _request_to_har(flow.request),
        "response": _response_to_har(flow.response, flow.request.url) if flow.response else {},
        "cache": {},
        "timings": {
            "blocked": -1,
            "dns": -1,
            "connect": -1,
            "send": 0,
            "wait": round(time_ms, 3),
            "receive": 0,
            "ssl": -1,
        },
    }
    if server_ip:
        entry["serverIPAddress"] = server_ip
    if flow.id:
        entry["connection"] = str(flow.id)
    if flow.comment:
        entry["comment"] = flow.comment
    return entry


def flows_to_har(
    flows: Sequence[http.HTTPFlow],
    title: str = "mitmproxy-mcp",
    creator: str = "mitmproxy-mcp",
) -> dict[str, Any]:
    """Convert a sequence of HTTPFlow objects to a HAR 1.2 document."""
    entries: list[dict[str, Any]] = []
    for flow in flows:
        entry = _flow_to_har_entry(flow)
        if entry is not None:
            entries.append(entry)

    return {
        "log": {
            "version": HAR_VERSION,
            "creator": {"name": creator, "version": "1.0"},
            "pages": [
                {
                    "startedDateTime": _iso_timestamp(entries[0]["request"].get("timestamp")) if entries else _iso_timestamp(None),
                    "id": "page_1",
                    "title": title,
                    "pageTimings": {"onContentLoad": -1, "onLoad": -1},
                }
            ],
            "entries": entries,
        }
    }


def _har_request_to_request(har_request: dict[str, Any]) -> http.Request:
    """Create a mitmproxy Request from a HAR request object."""
    method = str(har_request.get("method", "GET"))
    url = str(har_request.get("url", "http://localhost/"))
    headers = _headers_from_har(har_request.get("headers"))

    body = b""
    post_data = har_request.get("postData")
    if post_data:
        body = _decode_content_har(post_data)
        if not body and "params" in post_data:
            # Reconstruct application/x-www-form-urlencoded body.
            from urllib.parse import urlencode

            params = post_data["params"]
            if isinstance(params, list):
                body = urlencode([(p["name"], p["value"]) for p in params]).encode("utf-8")
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = http.Request.make(method, url, content=body, headers=headers)
    req.http_version = str(har_request.get("httpVersion", "HTTP/1.1"))
    return req


def _har_response_to_response(har_response: dict[str, Any]) -> http.Response | None:
    """Create a mitmproxy Response from a HAR response object."""
    if not har_response:
        return None

    status = har_response.get("status", 0)
    if not isinstance(status, int):
        try:
            status = int(status)
        except (TypeError, ValueError):
            return None

    headers = _headers_from_har(har_response.get("headers"))
    body = _decode_content_har(har_response.get("content"))

    resp = http.Response.make(status, content=body, headers=headers)
    resp.http_version = str(har_response.get("httpVersion", "HTTP/1.1"))
    resp.reason = str(har_response.get("statusText", ""))
    return resp


def _har_entry_to_flow(entry: dict[str, Any]) -> http.HTTPFlow | None:
    """Create a mitmproxy HTTPFlow from a HAR entry."""
    har_request = entry.get("request")
    if not har_request:
        return None

    try:
        req = _har_request_to_request(har_request)
    except Exception as e:
        logger.warning(f"Failed to parse HAR request: {e}")
        return None

    parsed = urlparse(req.url)
    host = parsed.hostname or req.host or "localhost"
    port = parsed.port or req.port or (443 if parsed.scheme == "https" else 80)

    client = Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0))
    server = Server(address=(host, port))
    flow = http.HTTPFlow(client, server)
    flow.request = req

    har_response = entry.get("response")
    if har_response:
        try:
            flow.response = _har_response_to_response(har_response)
        except Exception as e:
            logger.warning(f"Failed to parse HAR response: {e}")

    started = _parse_iso_timestamp(entry.get("startedDateTime"))
    req.timestamp_start = started
    time_ms = entry.get("time", 0)
    if isinstance(time_ms, (int, float)):
        req.timestamp_end = started + (time_ms / 1000.0)
    else:
        req.timestamp_end = started

    if flow.response:
        flow.response.timestamp_start = req.timestamp_end
        flow.response.timestamp_end = req.timestamp_end

    if entry.get("comment"):
        flow.comment = str(entry["comment"])

    return flow


def har_to_flows(har: dict[str, Any]) -> list[http.HTTPFlow]:
    """Convert a HAR document to a list of HTTPFlow objects."""
    log = har.get("log", {})
    entries = log.get("entries", [])
    flows: list[http.HTTPFlow] = []
    for idx, entry in enumerate(entries):
        try:
            flow = _har_entry_to_flow(entry)
            if flow is not None:
                flows.append(flow)
        except Exception as e:
            logger.warning(f"Skipping HAR entry {idx}: {e}")
    return flows


def save_har(path: str, flows: Sequence[http.HTTPFlow]) -> int:
    """Write flows to a HAR file. Returns number of entries written."""
    har = flows_to_har(flows)
    Path(path).write_text(json.dumps(har, indent=2), encoding="utf-8")
    return len(har["log"]["entries"])


def load_har(path: str) -> list[http.HTTPFlow]:
    """Read flows from a HAR file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return har_to_flows(data)
