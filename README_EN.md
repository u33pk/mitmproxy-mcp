# mitmproxy-mcp

A lightweight [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server built on [mitmproxy](https://mitmproxy.org/). It lets LLMs capture, inspect, replay and modify HTTP traffic through a small, focused set of tools.

## Features

- **Two capture modes**
  - Start a live proxy via `proxy_ctl(cmd="start")` and capture traffic in real time.
  - Load a previously saved `.mitm` dump with `flow_ctl(cmd="load")` for offline analysis.
- **Core operations**
  - **View**: `flow_ctl(cmd="list")`, `flow_ctl(cmd="get")`
  - **Replay**: `flow_action(action="replay")`, `flow_action(action="send")` — backed by mitmproxy's native `replay.client`
  - **Modify**: `flow_action(action="update")`, `flow_action(action="create")`
- **Built on mitmproxy's own engine** for replay and save, so we don't reinvent the wheel.
- **stdio transport** for out-of-the-box Claude Desktop compatibility.
- Uses mitmproxy's existing web UI (`mitmweb`) if you prefer a visual inspector.

## Install

Requires Python 3.13+ and `uv`.

```bash
uv venv
uv pip install -e .
```

## Claude Desktop configuration

Add this to your Claude Desktop config (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows/Linux paths may differ):

```json
{
  "mcpServers": {
    "mitmproxy": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mitmproxy-mcp",
        "run",
        "mitmproxy-mcp"
      ]
    }
  }
}
```

A sample config is also in [`examples/mcp-config.json`](examples/mcp-config.json).

## Quick start

1. Configure your browser or client to use the proxy address shown by `proxy_ctl(cmd="status")` (default `127.0.0.1:8080`).
2. Ask the LLM to run `proxy_ctl(cmd="start")`.
3. Browse or make API calls.
4. Ask the LLM to run `flow_ctl(cmd="list")` and `flow_ctl(cmd="get")` to inspect traffic.
5. Use `flow_action(action="replay")` to resend a request, or `flow_action(action="update")` + `flow_action(action="replay")` to modify and resend.

### Advanced proxy options

`proxy_ctl(cmd="start")` accepts an `extra_options` dictionary that is passed straight to mitmproxy's `options.Options`. This lets the LLM enable SOCKS5, raw TCP/UDP capture, host filtering, etc.

```json
{
  "host": "127.0.0.1",
  "port": 8080,
  "extra_options": {
    "mode": ["socks5"],
    "tcp_hosts": ["example.com"],
    "udp_hosts": ["dns.example.com"]
  }
}
```

Use `proxy_ctl(cmd="list_options")` to discover all available keys and their defaults.

### Large responses and JSON extraction

When inspecting flows with big bodies, use `flow_ctl(cmd="get")` with `max_content_size` to avoid flooding the LLM context:

```json
{
  "cmd": "get",
  "flow_id": 1,
  "max_content_size": 4096
}
```

- JSON bodies return a compact **structure preview**.
- Non-JSON text bodies are **truncated** with a note.

To pull specific values from JSON request or response bodies, use `flow_ctl(cmd="extract_json")` with [JSONPath](https://goessner.net/articles/JsonPath/) expressions:

```json
{
  "cmd": "extract_json",
  "flow_id": 1,
  "target": "response",
  "jsonpath": ["$.data.users[*].name", "$.meta.total"]
}
```

### HTTPS traffic

For HTTPS interception you must trust the mitmproxy CA certificate:

```bash
# Certificate location
~/.mitmproxy/mitmproxy-ca-cert.cer
```

Install it in your browser or system keychain. See [mitmproxy docs](https://docs.mitmproxy.org/stable/concepts-certificates/) for details.

### Certificate / CA management (`ca_ctl`)

`ca_ctl` is dedicated to certificate and CA settings, independent of `proxy_ctl`:

| Command | Purpose |
|---------|---------|
| `status` | Show current CA/certificate configuration |
| `export_ca` | Export the mitmproxy CA certificate to a directory |
| `set_verify_upstream` | Enable/disable upstream server certificate verification |
| `set_upstream_ca` | Set a CA file or directory for validating upstream servers |
| `clear_upstream_ca` | Remove the upstream CA setting |
| `set_client_cert` | Set an mTLS client certificate (optional key/passphrase) |
| `clear_client_cert` | Remove the client certificate setting |

Examples:

```python
# Export the CA so it can be installed on a client
ca_ctl(cmd="export_ca", output_dir="/tmp")

# Mutual verification: validate the upstream server with a custom CA
ca_ctl(cmd="set_verify_upstream", enabled=True)
ca_ctl(cmd="set_upstream_ca", ca_path="/path/to/server-ca.pem")

# mTLS
ca_ctl(cmd="set_client_cert", cert_path="/path/to/client.pem", key_path="/path/to/client.key")
```

Certificate config persists in `ProxyManager`, so it survives proxy stop/start. Changes also take effect immediately on a running proxy via mitmproxy's `set` command.

### Protocol metadata

Every flow now exposes protocol-layer metadata so you can distinguish HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) traffic:

```json
{
  "protocol": {
    "request_http_version": "HTTP/2",
    "response_http_version": "HTTP/2",
    "client_alpn": "h2",
    "server_alpn": "h2",
    "client_tls_version": "TLSv1.3",
    "server_tls_version": "TLSv1.3",
    "client_sni": "example.com",
    "server_sni": "example.com"
  }
}
```

In WireGuard mode, UDP/QUIC traffic is routed through mitmproxy, so HTTP/3 connections and their ALPN/TLS details are fully visible.

### WireGuard mode (cross-platform transparent proxy)

In addition to regular HTTP/SOCKS proxying, `proxy_ctl(cmd="start")` supports WireGuard mode. On start it auto-generates server and client keys and returns a WireGuard client config that can be imported into iOS, Android, macOS or Windows clients:

```json
{
  "cmd": "start",
  "host": "0.0.0.0",
  "port": 51820,
  "extra_options": {
    "mode": ["wireguard"]
  }
}
```

The returned `wireguard_config` field is the client INI. You can retrieve it again with `proxy_ctl(cmd="wireguard_config")`.

> Note: WireGuard is a Layer-3 VPN and captures all traffic (including QUIC/HTTP3), but you still need to trust the mitmproxy CA certificate to decrypt HTTPS/HTTP3 content.

### WebSocket traffic

WebSocket connections are captured as HTTP upgrade flows. After a client connects through the proxy, use the `websocket_only` filter to list WebSocket flows:

```json
{
  "cmd": "list",
  "websocket_only": true
}
```

Then call `flow_ctl(cmd="get", flow_id=...)` to see the full conversation:

```json
{
  "is_websocket": true,
  "websocket": {
    "messages": [
      {"from_client": true,  "type": "text", "text": "hello"},
      {"from_client": false, "type": "text", "text": "echo: hello"}
    ],
    "close_code": 1000
  }
}
```

Binary messages are base64-encoded (`content_encoding="base64"`). Use `max_content_size` on `flow_ctl(cmd="get")` to avoid large message payloads.

## Tools

| Tool | Commands / Description |
|------|------------------------|
| `proxy_ctl(cmd, ...)` | `start`, `stop`, `status`, `list_options`, `clear_all`, `wireguard_config` |
| `ca_ctl(cmd, ...)` | `status`, `export_ca`, `set_verify_upstream`, `set_upstream_ca`, `clear_upstream_ca`, `set_client_cert`, `clear_client_cert` |
| `flow_ctl(cmd, ...)` | `list`, `get`, `delete`, `clear`, `load`, `save`, `extract_json` |
| `flow_action(action, ...)` | `replay`, `resume`, `kill`, `update`, `create`, `send` |
| `rule_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` (automatic rules) |
| `capture_rule_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` (capture include/exclude rules) |
| `mock_server_ctl(cmd, ...)` | `start`, `add`, `stop`, `status` |
| `map_local_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` (URL → local file) |
| `map_remote_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` (URL rewrite) |
| `tool_info(tool_name, cmd=None)` | Progressive documentation for any tool/command |

Use `tool_info` to get detailed parameter descriptions and examples without bloating the static tool list. For example:

```json
{"tool_name": "proxy_ctl", "cmd": "start"}
```

## Automatic rules (breakpoints & modifications)

You can define rules that automatically match live traffic and apply actions. This is useful for mocking responses, injecting headers, blocking ads, or pausing requests for later inspection.

```json
{
  "id": "mock-api",
  "name": "Mock example API",
  "enabled": true,
  "phase": "request",
  "filter": "~u api.example.com/users",
  "actions": [
    {"type": "set_status", "status_code": 200},
    {"type": "set_header", "target": "response", "name": "Content-Type", "value": "application/json"},
    {"type": "set_body", "target": "response", "content": "{\"users\":[]}"}
  ]
}
```

Use `rule_ctl(cmd="add", rule=...)` to install the rule, `rule_ctl(cmd="list")` to inspect it, and `rule_ctl(cmd="clear")` to remove all rules.

Actions include: `set_header`, `remove_header`, `set_body`, `replace_body`, `set_status`, `set_path`, `set_method`, `delay`, `kill`, `intercept`, `resume`, `mark`, `comment`, `tag`.

The `filter` field uses mitmproxy's flowfilter syntax (`~u`, `~m`, `~h`, `~t`, `~c`, etc.). Use `intercept` to pause a matched flow, then call `flow_action(action="resume", flow_id=...)` or `flow_action(action="kill", flow_id=...)` from the LLM.

## Capture rules

Capture rules control which live flows are saved to memory. They support `include` and `exclude` actions and can be changed at runtime without restarting the proxy.

```json
[
  {"id": "api-only", "filter": "~u api.example.com", "action": "include"},
  {"id": "skip-health", "filter": "~u api.example.com/health", "action": "exclude"},
  {"id": "skip-images", "filter": "~t image/*", "action": "exclude"}
]
```

Logic:

- `exclude` rules are checked first; any match drops the flow.
- If any `include` rules exist, the flow must match at least one to be captured.
- The existing `capture_filter` option still applies as a base filter.

Use `capture_rule_ctl(cmd="add", rule=...)` to add rules, `capture_rule_ctl(cmd="list")` to inspect them, and `capture_rule_ctl(cmd="clear")` to remove all.

## Mock server (server-side playback)

Turn captured flows into a local mock server. Once started, matching requests receive the recorded response directly without contacting the real server.

```bash
# 1. Start the proxy and capture some real traffic
# 2. Use mock_server_start to replay the captured flows
```

```python
# Conceptual usage from an LLM:
mock_server_ctl(cmd="start", flow_ids=[1, 2, 3])
# Now requests matching the recorded ones return recorded responses.
mock_server_ctl(cmd="status")
mock_server_ctl(cmd="stop")
```

This is different from `flow_action(action="replay")`:

- `flow_action(action="replay")` re-sends the request to the real server.
- `mock_server_ctl(cmd="start")` intercepts incoming requests and returns recorded responses.

## URL mappings

Map requests to local files or rewrite URLs before forwarding.

### map_local

Serve local files for matching URLs:

```json
{
  "id": "api-mock",
  "filter": "~u example.com/api/data",
  "url_regex": "https://example.com/api/data",
  "local_path": "/path/to/mock.json"
}
```

### map_remote

Rewrite matching URLs to another origin:

```json
{
  "id": "staging-redirect",
  "filter": "~u example.com/api",
  "url_regex": "https://example.com/api(.*)",
  "replacement": "https://staging.example.com/api$1"
}
```

Use `map_local_ctl(cmd="add", rule=...)` / `map_remote_ctl(cmd="add", rule=...)` to add rules, `map_local_ctl(cmd="list")` / `map_remote_ctl(cmd="list")` to inspect them, and `*_ctl(cmd="clear")` to remove all.

## Playwright / browser automation

You can point Playwright at the mitmproxy-mcp proxy to capture browser traffic:

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(
        proxy={"server": "http://127.0.0.1:8080"},
        args=["--ignore-certificate-errors"],
    )
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    page.goto("https://example.com")
```

Then ask the LLM to run `flows_list` and inspect the captured requests.

A complete integration test is in [`tests/test_playwright_capture.py`](tests/test_playwright_capture.py). Run it with:

```bash
uv pip install -e ".[dev]"
playwright install chromium
python -m pytest tests/test_playwright_capture.py -m integration -v
```

## Development

Run the server manually for testing:

```bash
uv run mitmproxy-mcp
```

Run unit tests (excludes network/browser integration tests):

```bash
uv run pytest tests/ -q
```

Run integration tests:

```bash
# Playwright browser capture test
uv run pytest tests/test_playwright_capture.py -m integration -v

# All MCP tools end-to-end test
uv run pytest tests/test_all_tools.py -m integration -v
```

## License

MIT
