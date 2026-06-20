# mitmproxy-mcp

A lightweight MCP server built on mitmproxy. It exposes HTTP/WebSocket capture, replay, modification, mocking and URL mapping as composite MCP tools.

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
| `ca_ctl` | `status`, `export_ca`, `set_verify_upstream`, `set_upstream_ca`, `clear_upstream_ca`, `set_client_cert`, `clear_client_cert` | Certificate / CA management |
| `websocket_ctl` | `list`, `get`, `inject`, `connect`, `list_rules`, `add_rule`, `delete_rule`, `clear_rules` | WebSocket inspection / injection / rules |
| `http_ctl` | `list`, `get`, `delete`, `clear`, `load`, `save`, `extract_json` | Inspect/manage flows |
| `flow_action` | `replay`, `resume`, `kill`, `update`, `create`, `send` | Operate on flows |
| `crypt_ctl` | `list`, `load`, `unload`, `reload`, `status` | User-defined encryption/decryption scripts |
| `rule_ctl` | `list`, `add`, `delete`, `clear` | Automatic modification rules |
| `capture_rule_ctl` | `list`, `add`, `delete`, `clear` | Include/exclude capture rules |
| `mock_server_ctl` | `start`, `add`, `stop`, `status` | Server-side playback |
| `map_local_ctl` | `list`, `add`, `delete`, `clear` | URL → local file |
| `map_remote_ctl` | `list`, `add`, `delete`, `clear` | URL rewrite |
| `tool_info` | `tool_name`, `cmd` | Progressive documentation |

> Always prefer `tool_info(tool_name, cmd)` when you are unsure about parameters or need examples.
>
> **Security:** `crypt_ctl(cmd="load")` executes arbitrary Python from the given path. Only load scripts you trust.

## Common workflows

### 1. Capture live traffic

```python
proxy_ctl(cmd="start", port=8080)
# User configures browser/client to use 127.0.0.1:8080
proxy_ctl(cmd="status")
http_ctl(cmd="list", limit=20)
http_ctl(cmd="get", flow_id=1, max_content_size=4096)
```

### 2. Modify and replay a request

```python
flow_action(action="update", flow_id=1, request_path="/api/v2/users")
flow_action(action="replay", flow_id=1)
```

### 3. Mock an API with recorded flows

```python
# Capture real traffic first
http_ctl(cmd="list")
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

### 7. WebSocket traffic (`websocket_ctl`)

```python
# Inspect
websocket_ctl(cmd="list")
websocket_ctl(cmd="get", flow_id=5, max_content_size=4096)

# Inject into an existing connection
websocket_ctl(cmd="inject", flow_id=5, message="hello", to_client=False)

# Actively open a connection through the proxy
websocket_ctl(cmd="connect", url="ws://echo.example.com/", messages=["hello"], wait_for=1)

# Add a live modification rule
websocket_ctl(cmd="add_rule", rule={
    "id": "drop-ping",
    "direction": "client",
    "message_filter": "^ping$",
    "action": "drop",
})
```

### 8. Protocol metadata

Every flow exposes a `protocol` object with HTTP version, ALPN, TLS version and SNI for both client and server connections. Use it to identify HTTP/2 vs HTTP/3 (QUIC) traffic:

```python
http_ctl(cmd="get", flow_id=1)["flow"]["protocol"]
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

### 10. User-defined encryption/decryption (`crypt_ctl`)

For applications with user-space encryption, write a Python script that subclasses `CryptoHandler` and load it dynamically:

```python
crypt_ctl(cmd="load", script_path="/path/to/my_crypto.py")
http_ctl(cmd="get", flow_id=1)  # returns decrypted_content alongside raw content
flow_action(action="update", flow_id=1, decrypted_request_body='{"foo":"bar"}')
flow_action(action="replay", flow_id=1)  # addon re-encrypts before sending
```

Handlers can access the full `FlowStore` and keep cross-request state in `self.context`, enabling dynamic keys derived from earlier traffic (e.g. a `/auth/login` response).

### 11. TLS / certificate options (`ca_ctl`)

Use the dedicated `ca_ctl` tool for certificate management:

```python
# Export mitmproxy CA for client installation
ca_ctl(cmd="export_ca", output_dir="/tmp")

# Validate upstream server with a custom CA
ca_ctl(cmd="set_verify_upstream", enabled=True)
ca_ctl(cmd="set_upstream_ca", ca_path="/path/to/server-ca.pem")

# mTLS
ca_ctl(cmd="set_client_cert", cert_path="/path/to/client.pem", key_path="/path/to/client.key")
```

`ca_ctl` config persists across proxy stop/start. If you only need a quick test, `proxy_ctl(cmd="start", ssl_insecure=True)` still works.

## Best practices

- Start with `proxy_ctl(cmd="status")` to check whether the proxy is running.
- Use `tool_info(tool_name)` or `tool_info(tool_name, cmd="...")` whenever parameter details are needed.
- Use `max_content_size` in `http_ctl(cmd="get")` to avoid flooding context with large bodies.
- Capture rules use include/exclude logic; if no include rules exist, everything is captured.
- WebSocket connections are managed by `websocket_ctl`; use it for list, get, inject, connect and message modification rules.
- Check `flow["protocol"]` to see HTTP version, ALPN, TLS version and SNI.
- Use `crypt_ctl` for user-space encryption; decrypted plaintext appears in `flow["request"]["decrypted_content"]` / `flow["response"]["decrypted_content"]`.
- Use `tool_info("proxy_ctl", cmd="start")` and `tool_info("proxy_ctl", cmd="wireguard_config")` for details.

## Testing

```bash
uv run pytest tests/ -q
uv run pytest tests/test_all_tools.py tests/test_rules_integration.py tests/test_mock_server.py tests/test_mappings_integration.py tests/test_websocket_integration.py -m integration -q
```
