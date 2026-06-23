# Installation Guide for LLMs

This guide explains how to install the `mitmproxy-mcp` MCP server and register its skill so an LLM client (e.g. Claude Desktop) can use it.

## What is mitmproxy-mcp

`mitmproxy-mcp` is a Model Context Protocol (MCP) server built on [mitmproxy](https://mitmproxy.org/). It exposes HTTP/HTTPS traffic capture, replay, modification, WebSocket inspection, and custom encryption/decryption as MCP tools.

- **Language**: Python 3.13+
- **Package manager**: [uv](https://docs.astral.sh/uv/)
- **Transport**: `stdio` (default, Claude Desktop compatible) or `sse`
- **Entry point**: `mitmproxy-mcp` → `mitmproxy_mcp.server:main`

## Prerequisites

1. Python 3.13 or newer.
2. `uv` installed. If not, install it:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
3. Git (for source installation).

## Install the MCP server

### Option A: Install from source (recommended for development)

1. Clone the repository:
   ```bash
   git clone https://github.com/u33pk/mitmproxy-mcp.git
   cd mitmproxy-mcp
   ```

2. Create a virtual environment and install in editable mode:
   ```bash
   uv venv
   uv pip install -e .
   ```

3. (Optional) Install development dependencies if you want to run tests:
   ```bash
   uv pip install -e ".[dev]"
   ```

4. Verify the server starts:
   ```bash
   uv run mitmproxy-mcp
   # Should start and wait for MCP JSON-RPC messages on stdin.
   ```

### Option B: Install from PyPI

When the package is published:

```bash
uv pip install mitmproxy-mcp
```

Then run it directly:

```bash
uv run mitmproxy-mcp
```

## Configure an MCP client

### Claude Desktop (stdio transport)

Edit Claude Desktop's MCP configuration file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following server entry. Replace `/path/to/mitmproxy-mcp` with the absolute path to the repository root.

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

This uses `uv run` inside the project directory so the correct virtual environment is used.

### SSE transport (optional)

If you prefer to run the server as a standalone HTTP service and connect via SSE, start it with:

```bash
uv run python -m mitmproxy_mcp --transport sse --port 8081
```

Then configure the client with:

```json
{
  "mcpServers": {
    "mitmproxy": {
      "type": "sse",
      "url": "http://127.0.0.1:8081/sse"
    }
  }
}
```

> Note: the default and recommended transport for Claude Desktop is `stdio`.

## Install the skill

The skill files live in `.agents/skills/mitmproxy_mcp/`:

- `.agents/skills/mitmproxy_mcp/SKILL.md` — high-level workflows and common commands
- `.agents/skills/mitmproxy_mcp/references/crypto_handler.md` — how to write custom crypto handlers

### Register the skill

How skills are registered depends on the LLM client or agent framework you use. In general:

1. Make the skill directory discoverable by your agent system:
   ```
   .agents/skills/mitmproxy_mcp/
   ```

2. The agent should load `SKILL.md` as context when the user asks about:
   - capturing HTTP/HTTPS traffic
   - replaying or modifying flows
   - writing or loading custom encryption/decryption scripts
   - managing rules, mappings, or the CA certificate

3. For crypto handler authoring, also include `references/crypto_handler.md` as reference material.

If your agent framework requires a manifest or metadata file, create one that points to:

- `SKILL.md` as the primary skill document
- `references/crypto_handler.md` as a reference document

## Install the mitmproxy CA certificate

To capture HTTPS traffic, the client device/browser must trust mitmproxy's CA certificate.

1. Start the proxy:
   ```python
   proxy_ctl(cmd="start", port=8080)
   ```

2. Export the CA certificate:
   ```python
   ca_ctl(cmd="export_ca", path="/path/to/mitmproxy-ca-cert.pem")
   ```

3. Install the certificate on the client system or browser as a trusted root CA.

For local development, you can also find mitmproxy's default CA files in `~/.mitmproxy/`.

## Verify the installation

### Run unit tests

```bash
uv run pytest tests/ -q
```

Expected output: all unit tests pass.

### Run integration tests (optional)

These require a running proxy or browser environment:

```bash
# All MCP tools end-to-end
uv run pytest tests/test_all_tools.py -m integration -v

# URL mappings
uv run pytest tests/test_mappings_integration.py -m integration -v

# WebSocket capture
uv run pytest tests/test_websocket_integration.py -m integration -v
```

### Quick smoke test

1. Start the proxy via MCP:
   ```python
   proxy_ctl(cmd="start", port=8080, webui=True, web_port=8081)
   ```

2. Configure your browser to use `127.0.0.1:8080`.

3. Visit any HTTP/HTTPS site.

4. List captured flows:
   ```python
   http_ctl(cmd="list", limit=10)
   ```

5. Open the web UI at the URL returned by `proxy_ctl(cmd="status")`.

## Update or uninstall

### Update from source

```bash
cd /path/to/mitmproxy-mcp
git pull
uv pip install -e .
```

### Uninstall

```bash
uv pip uninstall mitmproxy-mcp
```

## Troubleshooting

- **`command not found: uv`**: make sure `uv` is installed and on your `PATH`.
- **Claude Desktop cannot start the server**: check that `--directory` points to the repository root and that `uv run mitmproxy-mcp` works when run manually in that directory.
- **HTTPS sites fail**: the mitmproxy CA certificate is not trusted on the client. Install it as a root CA.
- **Port already in use**: choose a different `port` or `web_port` when calling `proxy_ctl(cmd="start")`.
