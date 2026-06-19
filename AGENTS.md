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

# Integration: mock server
uv run pytest tests/test_mock_server.py -m integration -v

# Integration: URL mappings
uv run pytest tests/test_mappings_integration.py -m integration -v

# Integration: WebSocket capture
uv run pytest tests/test_websocket_integration.py -m integration -v

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
proxy.py       ProxyManager + CaptureAddon + RulesAddon + MappingState; runs mitmproxy DumpMaster in a thread
store.py       FlowStore: in-memory, thread-safe flow storage with CRUD/filtering
models.py      Pydantic models for HTTPFlow serialization
rules.py       Automatic rule engine: match flows and apply actions
mappings.py    MapLocalRule / MapRemoteRule models and MappingState
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

The server supports automatic rules via `rule_ctl`. A rule consists of:

- `id`, `name`, `enabled`
- `phase`: `"request"`, `"response"`, or `"both"`
- `filter`: a mitmproxy `flowfilter` expression (e.g. `~u example.com`, `~m POST`)
- `actions`: ordered list of actions to apply when matched

Supported actions include `set_header`, `remove_header`, `set_body`, `replace_body`, `set_status`, `set_path`, `set_method`, `delay`, `kill`, `intercept`, `resume`, `mark`, `comment`, `tag`.

Rules are evaluated by `RulesAddon` inside mitmproxy's `request`/`response` hooks. Applied rule ids are recorded in `flow.metadata["mitmproxy_mcp_rules_applied"]`.

To manually control intercepted flows, use `flow_action(action="resume", flow_id=...)` and `flow_action(action="kill", flow_id=...)`.

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

## WebSocket capture

WebSocket connections are represented by mitmproxy as `HTTPFlow` objects with a `websocket` attribute. The MCP server captures them automatically:

- The HTTP upgrade request/response is captured by the existing `response` hook.
- `CaptureAddon.websocket_start` ensures the flow is tracked.
- `CaptureAddon.websocket_message` updates `flow.metadata["websocket_message_count"]`.
- Messages accumulate on `flow.websocket.messages` and are serialized by `flow_to_model`.

Use `flow_ctl(cmd="list", websocket_only=True)` to find WebSocket flows and `flow_ctl(cmd="get", flow_id=...)` to inspect messages. Binary messages are base64-encoded; text messages expose both `content` and `text`.

## Capture rules

Capture rules decide which live flows are stored in `FlowStore`. They are managed via `capture_rule_ctl`.

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

## URL mappings

The server supports mitmproxy's `map_local` and `map_remote` addons through `map_local_ctl` and `map_remote_ctl`.

- `map_local_ctl` maps matching URLs to local files or directories.
- `map_remote_ctl` rewrites matching URLs to another remote URL.

Rules are stored in `MappingState` (`src/mitmproxy_mcp/mappings.py`) and synchronized to mitmproxy's `map_local` / `map_remote` options. The actual file serving and URL rewriting is handled by mitmproxy's native addons.

The `local_path` of a `MapLocalRule` must exist at the time the rule is added, because mitmproxy validates it when parsing the spec.

## Mock server

The mock server uses mitmproxy's `serverplayback` addon. It is exposed via `mock_server_ctl`:

- `mock_server_ctl(cmd="start", flow_ids=None, ignore_host=False, ignore_port=False, ignore_params=None, ignore_content=False, extra="forward")`
- `mock_server_ctl(cmd="add", flow_ids=...)`
- `mock_server_ctl(cmd="stop")`
- `mock_server_ctl(cmd="status")`

When active, matching incoming requests receive recorded responses without contacting the origin. This is different from `flow_action(action="replay")`, which re-sends requests to the real server.

The `store_id` field in `FlowModel` is the identifier LLMs should use with these tools (and with `flow_ctl(cmd="get")`, `flow_action(action="update")`, etc.).

## Adding a new tool

1. Define the function in `src/mitmproxy_mcp/server.py` with `@mcp.tool()`.
2. Keep the docstring minimal: one-line summary + command list + pointer to `tool_info`.
3. Add detailed docs to `src/mitmproxy_mcp/tool_info.py`.
4. Use Pydantic `Header` from `models.py` for header parameters.
5. Return `{"success": bool, ...}` shaped dicts for consistency.
6. Wrap internal exceptions and return `"error": str(e)` rather than crashing the server.
7. Add tests in `tests/test_server.py` or a new appropriate test file.

## Common commands

```bash
uv run pytest tests/ -q
uv run pytest tests/test_rules_integration.py -m integration -v
uv run pytest tests/test_mappings_integration.py -m integration -v
uv run mitmproxy-mcp
uv run python -m mitmproxy_mcp
uv pip install -e ".[dev]"
```

### Composite tools

| Tool | Commands |
|------|----------|
| `proxy_ctl(cmd, ...)` | `start`, `stop`, `status`, `list_options`, `clear_all` |
| `flow_ctl(cmd, ...)` | `list`, `get`, `delete`, `clear`, `load`, `save`, `extract_json` |
| `flow_action(action, ...)` | `replay`, `resume`, `kill`, `update`, `create`, `send` |
| `rule_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` |
| `capture_rule_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` |
| `mock_server_ctl(cmd, ...)` | `start`, `add`, `stop`, `status` |
| `map_local_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` |
| `map_remote_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear` |
| `tool_info(tool_name, cmd=None)` | Progressive documentation for any tool/command |

Use `proxy_ctl(cmd="clear_all", stop_proxy=False)` to clear all captured flows, automatic rules, capture rules and mappings in one call.

Use `tool_info(tool_name, cmd)` when the LLM needs detailed parameter descriptions or examples. This keeps the static tool schema small while preserving full documentation on demand.

### Progressive prompts

Tool docstrings are intentionally minimal (one-line summary + command list). Detailed docs live in `src/mitmproxy_mcp/tool_info.py` and are exposed via `tool_info`. Rule-like tools accept plain `dict` payloads rather than full Pydantic models, reducing the static schema size significantly.
