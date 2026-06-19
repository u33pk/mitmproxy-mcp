# AGENTS.md — mitmproxy-mcp

## Project overview

A lightweight [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server built on [mitmproxy](https://mitmproxy.org/). It exposes mitmproxy capture, replay and modification capabilities as MCP tools so LLMs can inspect and manipulate HTTP traffic.

- **Language**: Python 3.13+
- **Package manager**: `uv`
- **Entry point**: `mitmproxy-mcp` → `mitmproxy_mcp.server:main`
- **Transport**: `stdio` (Claude Desktop compatible)

## Development setup

Use `uv` for all Python operations. Do not use the system `python`/`pip` directly.

```bash
# Create virtual environment and install in editable mode
uv venv
uv pip install -e .

# Install with dev dependencies (tests)
uv pip install -e ".[dev]"
```

## Running the server

```bash
# Manual run
uv run mitmproxy-mcp

# Module invocation
uv run python -m mitmproxy_mcp
```

Logs are written to `stderr` to keep `stdout` clean for MCP stdio.

## Testing

```bash
# Unit tests only (default; excludes integration tests)
uv run pytest tests/ -q

# Integration: all MCP tools end-to-end
uv run pytest tests/test_all_tools.py -m integration -v

# Integration: automatic rules and capture rules
uv run pytest tests/test_rules_integration.py -m integration -v

# Integration: Playwright browser capture
uv pip install -e ".[dev]"
playwright install chromium
uv run pytest tests/test_playwright_capture.py -m integration -v
```

Integration tests require a running proxy or a browser environment.

## Code conventions

- Use `from __future__ import annotations` in new modules.
- Type hints are required for public functions.
- Prefer `dict[str, Any]` over bare `dict` in signatures.
- Content encoding is modeled as `Literal["text", "base64"]`.
- Binary bodies are base64-encoded; text bodies are UTF-8 strings.
- Keep stdout clean: log to `stderr` only.
- Use `threading.RLock` for thread-safe shared state (`FlowStore`, `ProxyManager`).

## Architecture

```
server.py      FastMCP server; defines all tools
proxy.py       ProxyManager + CaptureAddon + RulesAddon; runs mitmproxy DumpMaster in a thread
store.py       FlowStore: in-memory, thread-safe flow storage with CRUD/filtering
models.py      Pydantic models for HTTPFlow serialization
rules.py       Automatic rule engine: match flows and apply actions
json_tools.py  JSONPath extraction and large-body preview helpers
utils.py       Helpers: create_http_flow, replay_flows, save_flows, decode_body
```

### Important patterns

- `FlowStore` assigns monotonically increasing integer IDs (`mitmproxy_mcp_id`) to each `HTTPFlow`.
- `ProxyManager.call()` is the only thread-safe way to invoke mitmproxy commands on the running event loop.
- Replay and save use mitmproxy's native commands (`replay.client`, `save.file`) rather than reimplementing logic.
- `CaptureAddon` filters flows with `capture_filter` and a runtime-updatable list of `CaptureRule` objects (`include`/`exclude`).
- `RulesAddon` runs inside the mitmproxy event loop; its rule list is protected by an `RLock` and can be updated from the MCP tool thread.

## Automatic rules

The server supports automatic rules via `rules_*` tools. A rule consists of:

- `id`, `name`, `enabled`
- `phase`: `"request"`, `"response"`, or `"both"`
- `filter`: a mitmproxy `flowfilter` expression (e.g. `~u example.com`, `~m POST`)
- `actions`: ordered list of actions to apply when matched

Supported actions include `set_header`, `remove_header`, `set_body`, `replace_body`, `set_status`, `set_path`, `set_method`, `delay`, `kill`, `intercept`, `resume`, `mark`, `comment`, `tag`.

Rules are evaluated by `RulesAddon` inside mitmproxy's `request`/`response` hooks. Applied rule ids are recorded in `flow.metadata["mitmproxy_mcp_rules_applied"]`.

To manually control intercepted flows, use `flow_resume` and `flow_kill`.

### Example rule

```json
{
  "id": "block-assets",
  "name": "Block image requests",
  "enabled": true,
  "phase": "request",
  "filter": "~t image/*",
  "actions": [
    {"type": "set_status", "status_code": 404},
    {"type": "kill"}
  ]
}
```

## Capture rules

Capture rules decide which live flows are stored in `FlowStore`. They are managed via `capture_rules_*` tools.

- `action`: `"include"` or `"exclude"`
- `filter`: a mitmproxy `flowfilter` expression

Decision logic:

1. If `capture_filter` is set, the flow must pass it first.
2. If no capture rules exist, the flow is captured.
3. All enabled `exclude` rules are evaluated; any match drops the flow.
4. If enabled `include` rules exist, the flow must match at least one; otherwise it is dropped.
5. If there are no enabled `include` rules and no `exclude` matched, the flow is captured.

Capture rules are evaluated inside `CaptureAddon.response`/`error` hooks. The rule list is thread-safe and can be updated while the proxy is running.

### Example capture rules

Only capture API traffic and ignore health checks:

```json
[
  {"id": "api-only", "filter": "~u api.example.com", "action": "include"},
  {"id": "skip-health", "filter": "~u api.example.com/health", "action": "exclude"}
]
```

## Adding a new tool

1. Define the function in `src/mitmproxy_mcp/server.py` with `@mcp.tool()`.
2. Use Pydantic `Header` from `models.py` for header parameters.
3. Return `{"success": bool, ...}` shaped dicts for consistency.
4. Wrap internal exceptions and return `"error": str(e)` rather than crashing the server.
5. Add tests in `tests/test_server.py` or a new appropriate test file.

## Common commands

```bash
uv run pytest tests/ -q
uv run pytest tests/test_rules_integration.py -m integration -v
uv run mitmproxy-mcp
uv run python -m mitmproxy_mcp
uv pip install -e ".[dev]"
```

### Utility tools

- `clear_all(stop_proxy=False)` — clear all captured flows, automatic rules and capture rules in one call.
