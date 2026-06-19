# mitmproxy-mcp

A lightweight [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server built on [mitmproxy](https://mitmproxy.org/). It lets LLMs capture, inspect, replay and modify HTTP traffic through a small, focused set of tools.

## Features

- **Two capture modes**
  - Start a live proxy via `proxy_start` and capture traffic in real time.
  - Load a previously saved `.mitm` dump with `flows_load` for offline analysis.
- **Core operations**
  - **View**: `flows_list`, `flow_get`
  - **Replay**: `flow_replay`, `request_send` — backed by mitmproxy's native `replay.client`
  - **Modify**: `flow_update`, `flow_create`
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

1. Configure your browser or client to use the proxy address shown by `proxy_status` (default `127.0.0.1:8080`).
2. Ask the LLM to run `proxy_start`.
3. Browse or make API calls.
4. Ask the LLM to run `flows_list` and `flow_get` to inspect traffic.
5. Use `flow_replay` to resend a request, or `flow_update` + `flow_replay` to modify and resend.

### Advanced proxy options

`proxy_start` accepts an `extra_options` dictionary that is passed straight to mitmproxy's `options.Options`. This lets the LLM enable SOCKS5, raw TCP/UDP capture, host filtering, etc.

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

Use `proxy_list_options` to discover all available keys and their defaults.

### Large responses and JSON extraction

When inspecting flows with big bodies, use `flow_get` with `max_content_size` to avoid flooding the LLM context:

```json
{
  "flow_id": 1,
  "max_content_size": 4096
}
```

- JSON bodies return a compact **structure preview**.
- Non-JSON text bodies are **truncated** with a note.

To pull specific values from JSON request or response bodies, use `flow_extract_json` with [JSONPath](https://goessner.net/articles/JsonPath/) expressions:

```json
{
  "flow_id": 1,
  "content_type": "response",
  "json_paths": ["$.data.users[*].name", "$.meta.total"]
}
```

### HTTPS traffic

For HTTPS interception you must trust the mitmproxy CA certificate:

```bash
# Certificate location
~/.mitmproxy/mitmproxy-ca-cert.cer
```

Install it in your browser or system keychain. See [mitmproxy docs](https://docs.mitmproxy.org/stable/concepts-certificates/) for details.

## Tools

| Tool | Description |
|------|-------------|
| `proxy_start` | Start the capture proxy (`host`, `port`, `capture_filter`, `ssl_insecure`, `upstream_proxy`, `extra_options`) |
| `proxy_stop` | Stop the capture proxy |
| `proxy_status` | Show proxy state and number of captured flows |
| `proxy_list_options` | List available mitmproxy-native options for `extra_options` |
| `flows_load` | Load flows from a `.mitm` file |
| `flows_save` | Save current flows to a `.mitm` file |
| `flows_list` | List flows with filtering/pagination |
| `flow_get` | Get a single flow's full details (optionally truncate/preview large bodies) |
| `flow_extract_json` | Extract fields from JSON request/response content using JSONPath |
| `flows_clear` | Clear in-memory flows; optionally stop proxy |
| `flow_replay` | Replay a flow using mitmproxy's `replay.client` |
| `flow_resume` | Resume an intercepted (breakpoint-paused) flow |
| `flow_kill` | Kill a running or intercepted flow |
| `request_send` | Send a new request using mitmproxy's `replay.client` |
| `flow_update` | Modify a flow's request/response or metadata |
| `flow_create` | Create a new request flow without sending |
| `flow_delete` | Delete a flow from memory |
| `rules_list` | List configured automatic rules |
| `rule_add` | Add or replace an automatic rule |
| `rule_update` | Update an automatic rule |
| `rule_delete` | Delete an automatic rule |
| `rules_clear` | Delete all automatic rules |
| `clear_all` | Clear all flows, rules and capture rules at once |
| `capture_rules_list` | List configured capture rules |
| `capture_rule_add` | Add or replace a capture rule |
| `capture_rule_update` | Update a capture rule |
| `capture_rule_delete` | Delete a capture rule |
| `capture_rules_clear` | Delete all capture rules |
| `mock_server_start` | Start a mock server from captured flows |
| `mock_server_add_flows` | Add more flows to the mock server |
| `mock_server_stop` | Stop the mock server |
| `mock_server_status` | Show the number of mocked flows |

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

Use `rule_add` to install the rule, `rules_list` to inspect it, and `rules_clear` to remove all rules.

Actions include: `set_header`, `remove_header`, `set_body`, `replace_body`, `set_status`, `set_path`, `set_method`, `delay`, `kill`, `intercept`, `resume`, `mark`, `comment`, `tag`.

The `filter` field uses mitmproxy's flowfilter syntax (`~u`, `~m`, `~h`, `~t`, `~c`, etc.). Use `intercept` to pause a matched flow, then call `flow_resume` or `flow_kill` from the LLM.

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

Use `capture_rule_add` to add rules, `capture_rules_list` to inspect them, and `capture_rules_clear` to remove all.

## Mock server (server-side playback)

Turn captured flows into a local mock server. Once started, matching requests receive the recorded response directly without contacting the real server.

```bash
# 1. Start the proxy and capture some real traffic
# 2. Use mock_server_start to replay the captured flows
```

```python
# Conceptual usage from an LLM:
mock_server_start(flow_ids=[1, 2, 3])
# Now requests matching the recorded ones return recorded responses.
mock_server_status()
mock_server_stop()
```

This is different from `flow_replay`:

- `flow_replay` re-sends the request to the real server.
- `mock_server_start` intercepts incoming requests and returns recorded responses.

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
