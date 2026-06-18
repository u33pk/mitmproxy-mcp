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
| `proxy_start` | Start the capture proxy (`host`, `port`, `capture_filter`, `ssl_insecure`, `upstream_proxy`) |
| `proxy_stop` | Stop the capture proxy |
| `proxy_status` | Show proxy state and number of captured flows |
| `flows_load` | Load flows from a `.mitm` file |
| `flows_save` | Save current flows to a `.mitm` file |
| `flows_list` | List flows with filtering/pagination |
| `flow_get` | Get a single flow's full details |
| `flows_clear` | Clear in-memory flows; optionally stop proxy |
| `flow_replay` | Replay a flow using mitmproxy's `replay.client` |
| `request_send` | Send a new request using mitmproxy's `replay.client` |
| `flow_update` | Modify a flow's request/response or metadata |
| `flow_create` | Create a new request flow without sending |
| `flow_delete` | Delete a flow from memory |

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
