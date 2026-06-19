# mitmproxy-mcp

A lightweight MCP server built on mitmproxy. It exposes HTTP/WebSocket capture, replay, modification, mocking and URL mapping as 8 composite MCP tools.

## When to use

Use this skill when the user wants to:

- Capture and inspect HTTP/HTTPS/WebSocket traffic
- Replay, modify or create HTTP requests
- Set up automatic request/response modification rules
- Mock APIs using recorded responses
- Rewrite URLs or serve local files for matching requests

## Installation / running

```bash
uv venv
uv pip install -e ".[dev]"
uv run mitmproxy-mcp
```

Entry point: `mitmproxy_mcp.server:main` (stdio transport for Claude Desktop).

## Tools overview

| Tool | Commands | Purpose |
|------|----------|---------|
| `proxy_ctl` | `start`, `stop`, `status`, `list_options`, `clear_all`, `wireguard_config` | Proxy lifecycle |
| `flow_ctl` | `list`, `get`, `delete`, `clear`, `load`, `save`, `extract_json` | Inspect/manage flows |
| `flow_action` | `replay`, `resume`, `kill`, `update`, `create`, `send` | Operate on flows |
| `rule_ctl` | `list`, `add`, `delete`, `clear` | Automatic modification rules |
| `capture_rule_ctl` | `list`, `add`, `delete`, `clear` | Include/exclude capture rules |
| `mock_server_ctl` | `start`, `add`, `stop`, `status` | Server-side playback |
| `map_local_ctl` | `list`, `add`, `delete`, `clear` | URL → local file |
| `map_remote_ctl` | `list`, `add`, `delete`, `clear` | URL rewrite |
| `tool_info` | `tool_name`, `cmd` | Progressive documentation |

> Always prefer `tool_info(tool_name, cmd)` when you are unsure about parameters or need examples.

## Common workflows

### 1. Capture live traffic

```python
proxy_ctl(cmd="start", port=8080)
# User configures browser/client to use 127.0.0.1:8080
proxy_ctl(cmd="status")
flow_ctl(cmd="list", limit=20)
flow_ctl(cmd="get", flow_id=1, max_content_size=4096)
```

### 2. Modify and replay a request

```python
flow_action(action="update", flow_id=1, request_path="/api/v2/users")
flow_action(action="replay", flow_id=1)
```

### 3. Mock an API with recorded flows

```python
# Capture real traffic first
flow_ctl(cmd="list")
mock_server_ctl(cmd="start", flow_ids=[1, 2])
mock_server_ctl(cmd="status")
mock_server_ctl(cmd="stop")
```

### 4. Add an automatic rule

```python
rule_ctl(cmd="add", rule={
    "id": "mock-users",
    "filter": "~u api.example.com/users",
    "phase": "response",
    "actions": [
        {"type": "set_status", "status_code": 200},
        {"type": "set_header", "target": "response", "name": "Content-Type", "value": "application/json"},
        {"type": "set_body", "target": "response", "content": '{"users":[]}'},
    ],
})
rule_ctl(cmd="list")
```

### 5. Capture only specific traffic

```python
capture_rule_ctl(cmd="add", rule={
    "id": "api-only",
    "filter": "~u api.example.com",
    "action": "include",
})
capture_rule_ctl(cmd="add", rule={
    "id": "skip-health",
    "filter": "~u api.example.com/health",
    "action": "exclude",
})
```

### 6. URL mappings

```python
map_local_ctl(cmd="add", rule={
    "id": "api-mock",
    "filter": "~u example.com/api/data",
    "url_regex": "https://example.com/api/data",
    "local_path": "/tmp/mock.json",
})

map_remote_ctl(cmd="add", rule={
    "id": "staging",
    "filter": "~u example.com/api",
    "url_regex": "https://example.com/api(.*)",
    "replacement": "https://staging.example.com/api$1",
})
```

### 7. WebSocket traffic

```python
flow_ctl(cmd="list", websocket_only=True)
flow_ctl(cmd="get", flow_id=5, max_content_size=4096)
```

### 8. Protocol metadata

Every flow exposes a `protocol` object with HTTP version, ALPN, TLS version and SNI for both client and server connections. Use it to identify HTTP/2 vs HTTP/3 (QUIC) traffic:

```python
flow_ctl(cmd="get", flow_id=1)["flow"]["protocol"]
```

### 9. WireGuard transparent proxy

Start the proxy in WireGuard mode to capture all traffic (including QUIC/HTTP3) from iOS, Android, macOS or Windows clients:

```python
proxy_ctl(
    cmd="start",
    host="0.0.0.0",
    port=51820,
    extra_options={"mode": ["wireguard"]},
)
# Returns a wireguard_config INI for the client.
proxy_ctl(cmd="wireguard_config")
```

> Trust the mitmproxy CA on the client to decrypt HTTPS/HTTP3.

### 10. TLS / certificate options

- `ssl_insecure=True` skips upstream server certificate verification.
- For custom upstream CA or mTLS, pass mitmproxy native options via `extra_options`:

```python
proxy_ctl(cmd="start", extra_options={
    "ssl_verify_upstream": True,
    "ssl_ca_file": "/path/to/server-ca.pem",
    "client_certs": "/path/to/client-cert.pem",
})
```

## Best practices

- Start with `proxy_ctl(cmd="status")` to check whether the proxy is running.
- Use `tool_info(tool_name)` or `tool_info(tool_name, cmd="...")` whenever parameter details are needed.
- Use `max_content_size` in `flow_ctl(cmd="get")` to avoid flooding context with large bodies.
- Capture rules use include/exclude logic; if no include rules exist, everything is captured.
- WebSocket connections appear as HTTP upgrade flows with `is_websocket=True` and a `websocket.messages` list.
- Check `flow["protocol"]` to see HTTP version, ALPN, TLS version and SNI.
- Use `tool_info("proxy_ctl", cmd="start")` and `tool_info("proxy_ctl", cmd="wireguard_config")` for details.

## Testing

```bash
uv run pytest tests/ -q
uv run pytest tests/test_all_tools.py tests/test_rules_integration.py tests/test_mock_server.py tests/test_mappings_integration.py tests/test_websocket_integration.py -m integration -q
```
