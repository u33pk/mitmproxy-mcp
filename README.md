# mitmproxy-mcp

一个基于 [mitmproxy](https://mitmproxy.org/) 构建的轻量级 [Model Context Protocol (MCP)](https://modelcontextprotocol.io) 服务器。它让 LLM 可以通过一小套工具来捕获、检查、重放和修改 HTTP 流量。

## 特性

- **两种捕获模式**
  - 通过 `proxy_ctl(cmd="start")` 启动实时代理，实时捕获流量。
  - 通过 `http_ctl(cmd="load")` 加载之前保存的 `.mitm` 文件进行离线分析。
- **核心操作**
  - **查看**: `http_ctl(cmd="list")`, `http_ctl(cmd="get")`
  - **重放**: `flow_action(action="replay")`, `flow_action(action="send")` —— 基于 mitmproxy 原生 `replay.client`
  - **修改**: `flow_action(action="update")`, `flow_action(action="create")`
- **基于 mitmproxy 自身引擎** 实现重放和保存，不重复造轮子。
- **stdio 传输**，开箱兼容 Claude Desktop。
- **SSE 传输**，可远程或网络客户端连接（Claude Code、Cursor 等）。
- 如需可视化界面，可直接使用 mitmproxy 自带的 Web UI（`mitmweb`）。

## 安装

需要 Python 3.13+ 和 `uv`。

```bash
uv venv
uv pip install -e .
```

## Claude Desktop 配置

将以下内容添加到你的 Claude Desktop 配置中（macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`，Windows/Linux 路径可能不同）：

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

示例配置也可参考 [`examples/mcp-config.json`](examples/mcp-config.json)。

### SSE 配置（Claude Code / 远程客户端）

启动 SSE 服务器：

```bash
uv run mitmproxy-mcp --transport sse --host 127.0.0.1 --port 8081
```

然后在 MCP 客户端配置中连接：

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

## 快速开始

1. 将浏览器或客户端配置为使用 `proxy_ctl(cmd="status")` 显示的代理地址（默认 `127.0.0.1:8080`）。
2. 让 LLM 执行 `proxy_ctl(cmd="start")`。
3. 浏览网页或调用 API。
4. 让 LLM 执行 `http_ctl(cmd="list")` 和 `http_ctl(cmd="get")` 检查流量。
5. 使用 `flow_action(action="replay")` 重发请求，或用 `flow_action(action="update")` + `flow_action(action="replay")` 修改后重发。

### 高级代理选项

`proxy_ctl(cmd="start")` 接受 `extra_options` 字典，直接透传给 mitmproxy 的 `options.Options`。这样 LLM 可以启用 SOCKS5、原始 TCP/UDP 捕获、主机过滤等。

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

使用 `proxy_ctl(cmd="list_options")` 查看所有可用键及其默认值。

### 大响应与 JSON 提取

检查大体积响应体时，使用 `http_ctl(cmd="get")` 的 `max_content_size` 避免占满 LLM 上下文：

```json
{
  "cmd": "get",
  "flow_id": 1,
  "max_content_size": 4096
}
```

- JSON 体会返回紧凑的 **结构预览**。
- 非 JSON 文本体会 **截断** 并附加提示。

要从 JSON 请求或响应体中提取特定值，使用 `http_ctl(cmd="extract_json")` 配合 [JSONPath](https://goessner.net/articles/JsonPath/) 表达式：

```json
{
  "cmd": "extract_json",
  "flow_id": 1,
  "target": "response",
  "jsonpath": ["$.data.users[*].name", "$.meta.total"]
}
```

### HTTPS 流量

拦截 HTTPS 需要信任 mitmproxy 的 CA 证书：

```bash
# 证书位置
~/.mitmproxy/mitmproxy-ca-cert.cer
```

将其安装到浏览器或系统钥匙串。详见 [mitmproxy 文档](https://docs.mitmproxy.org/stable/concepts-certificates/)。

### 证书 / CA 管理 (`ca_ctl`)

`ca_ctl` 专门管理证书与 CA 设置，独立于 `proxy_ctl`：

| 命令 | 作用 |
|------|------|
| `status` | 查看当前 CA/证书配置 |
| `export_ca` | 导出 mitmproxy CA 证书到指定目录 |
| `set_verify_upstream` | 启用/禁用上游服务器证书校验 |
| `set_upstream_ca` | 设置校验上游用的 CA 文件或目录 |
| `clear_upstream_ca` | 清空上游 CA 设置 |
| `set_client_cert` | 设置 mTLS 客户端证书（可选 key/passphrase） |
| `clear_client_cert` | 清空客户端证书 |

示例：

```python
# 导出 CA 给客户端安装
ca_ctl(cmd="export_ca", output_dir="/tmp")

# 双向校验：用指定 CA 验证上游服务器
ca_ctl(cmd="set_verify_upstream", enabled=True)
ca_ctl(cmd="set_upstream_ca", ca_path="/path/to/server-ca.pem")

# mTLS
ca_ctl(cmd="set_client_cert", cert_path="/path/to/client.pem", key_path="/path/to/client.key")
```

证书配置会持久保存在 `ProxyManager` 中，代理停止/重启后仍然有效；代理运行期间设置会立即通过 mitmproxy `set` 命令生效。

### 协议元数据

每条流现在都会暴露协议层元数据，便于区分 HTTP/1.1、HTTP/2 和 HTTP/3（QUIC）流量：

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

在 WireGuard 模式下，UDP/QUIC 流量会被路由到 mitmproxy，因此可以完整观察到 HTTP/3 连接及其 ALPN/TLS 信息。

### WireGuard 模式（跨平台透明代理）

除了常规 HTTP/SOCKS 代理，`proxy_ctl(cmd="start")` 还支持 WireGuard 模式。启动时会自动生成服务端与客户端密钥，并返回可直接导入 iOS、Android、macOS、Windows 的 WireGuard 客户端配置：

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

返回的 `wireguard_config` 字段即为客户端 INI 配置。之后可通过 `proxy_ctl(cmd="wireguard_config")` 再次获取。

> 注意：WireGuard 是 Layer-3 VPN，会捕获所有流量（包括 QUIC/HTTP3），但仍需信任 mitmproxy CA 证书才能解密 HTTPS/HTTP3 内容。

### WebSocket 流量（`websocket_ctl`）

WebSocket 连接以 HTTP upgrade 流的形式被捕获，现在由独立的 `websocket_ctl` 工具管理：

```python
# 列出 WebSocket 流
websocket_ctl(cmd="list")

# 查看完整会话
websocket_ctl(cmd="get", flow_id=1, max_content_size=4096)
```

返回结构：

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

二进制消息会 base64 编码（`content_encoding="base64"`）。

#### 消息注入

向已建立的 WebSocket 连接主动发消息：

```python
websocket_ctl(cmd="inject", flow_id=1, message="hello from mcp", to_client=False)
```

- `to_client=True` 发给客户端，`to_client=False` 发给服务端。
- `binary=True` 时以二进制帧发送。

#### 主动发起连接

MCP 服务器自己作为客户端，经代理连接目标 WebSocket：

```python
websocket_ctl(
    cmd="connect",
    url="ws://echo.example.com/",
    messages=["hello"],
    wait_for=1,
    timeout=10,
)
```

返回里会包含捕获到的 `flow_id` 和收到的消息列表。

#### 规则化修改

对实时 WebSocket 消息设置修改/丢弃规则：

```python
websocket_ctl(cmd="add_rule", rule={
    "id": "drop-ping",
    "flow_filter": "~d api.example.com",
    "direction": "client",
    "message_filter": "^ping$",
    "action": "drop",
})

websocket_ctl(cmd="add_rule", rule={
    "id": "replace-echo",
    "direction": "server",
    "message_filter": "echo:",
    "action": "replace_regex",
    "replacement_regex": "echo:",
    "replacement": "modified:",
})
```

支持的动作：`drop`、`replace`、`replace_regex`。

## 工具

| 工具 | 命令 / 说明 |
|------|------------|
| `proxy_ctl(cmd, ...)` | `start`, `stop`, `status`, `list_options`, `clear_all`, `wireguard_config` |
| `ca_ctl(cmd, ...)` | `status`, `export_ca`, `set_verify_upstream`, `set_upstream_ca`, `clear_upstream_ca`, `set_client_cert`, `clear_client_cert` |
| `websocket_ctl(cmd, ...)` | `list`, `get`, `inject`, `connect`, `list_rules`, `add_rule`, `delete_rule`, `clear_rules` |
| `http_ctl(cmd, ...)` | `list`, `get`, `delete`, `clear`, `load`, `save`, `extract_json` |
| `flow_action(action, ...)` | `replay`, `resume`, `kill`, `update`, `create`, `send` |
| `rule_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear`（自动规则） |
| `capture_rule_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear`（捕获 include/exclude 规则） |
| `mock_server_ctl(cmd, ...)` | `start`, `add`, `stop`, `status` |
| `map_local_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear`（URL → 本地文件） |
| `map_remote_ctl(cmd, ...)` | `list`, `add`, `delete`, `clear`（URL 重写） |
| `tool_info(tool_name, cmd=None)` | 任何工具/命令的渐进式文档 |

使用 `tool_info` 获取详细的参数说明和示例，而不必让静态工具列表变得臃肿。例如：

```json
{"tool_name": "proxy_ctl", "cmd": "start"}
```

## 自动规则（断点与修改）

你可以定义自动匹配实时流量并执行操作的规则。适用于模拟响应、注入请求头、拦截广告或暂停请求以便后续检查。

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

使用 `rule_ctl(cmd="add", rule=...)` 安装规则，`rule_ctl(cmd="list")` 查看，`rule_ctl(cmd="clear")` 移除全部规则。

支持的操作包括：`set_header`, `remove_header`, `set_body`, `replace_body`, `set_status`, `set_path`, `set_method`, `delay`, `kill`, `intercept`, `resume`, `mark`, `comment`, `tag`。

`filter` 字段使用 mitmproxy 的 flowfilter 语法（`~u`, `~m`, `~h`, `~t`, `~c` 等）。使用 `intercept` 暂停匹配的流，然后由 LLM 调用 `flow_action(action="resume", flow_id=...)` 或 `flow_action(action="kill", flow_id=...)`。

## 捕获规则

捕获规则决定哪些实时流量会被保存到内存。支持 `include` 和 `exclude` 操作，且可在代理运行时动态修改而无需重启。

```json
[
  {"id": "api-only", "filter": "~u api.example.com", "action": "include"},
  {"id": "skip-health", "filter": "~u api.example.com/health", "action": "exclude"},
  {"id": "skip-images", "filter": "~t image/*", "action": "exclude"}
]
```

逻辑：

- `exclude` 规则优先检查；任意匹配则丢弃该流。
- 如果存在任意 `include` 规则，则流必须至少匹配其中一个才会被捕获。
- 基础的 `capture_filter` 选项仍会作为前置过滤。

使用 `capture_rule_ctl(cmd="add", rule=...)` 添加规则，`capture_rule_ctl(cmd="list")` 查看，`capture_rule_ctl(cmd="clear")` 移除全部。

## Mock 服务器（服务端回放）

将捕获到的流变成本地 Mock 服务器。启动后，匹配请求会直接返回录制响应，无需访问真实服务器。

```bash
# 1. 启动代理并捕获一些真实流量
# 2. 使用 mock_server_start 回放已捕获的流
```

```python
# LLM 的概念用法：
mock_server_ctl(cmd="start", flow_ids=[1, 2, 3])
# 现在匹配录制请求的访问会返回录制响应。
mock_server_ctl(cmd="status")
mock_server_ctl(cmd="stop")
```

这与 `flow_action(action="replay")` 不同：

- `flow_action(action="replay")` 会向真实服务器重新发送请求。
- `mock_server_ctl(cmd="start")` 会拦截入站请求并返回录制响应。

## URL 映射

将请求映射到本地文件，或在转发前重写 URL。

### map_local

为匹配 URL 提供本地文件：

```json
{
  "id": "api-mock",
  "filter": "~u example.com/api/data",
  "url_regex": "https://example.com/api/data",
  "local_path": "/path/to/mock.json"
}
```

### map_remote

将匹配 URL 重写为另一个源站：

```json
{
  "id": "staging-redirect",
  "filter": "~u example.com/api",
  "url_regex": "https://example.com/api(.*)",
  "replacement": "https://staging.example.com/api$1"
}
```

使用 `map_local_ctl(cmd="add", rule=...)` / `map_remote_ctl(cmd="add", rule=...)` 添加规则，`map_local_ctl(cmd="list")` / `map_remote_ctl(cmd="list")` 查看，`*_ctl(cmd="clear")` 移除全部。

## Playwright / 浏览器自动化

你可以将 Playwright 指向 mitmproxy-mcp 代理来捕获浏览器流量：

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

然后让 LLM 执行 `flows_list` 并检查捕获的请求。

完整集成测试见 [`tests/test_playwright_capture.py`](tests/test_playwright_capture.py)。运行方式：

```bash
uv pip install -e ".[dev]"
playwright install chromium
python -m pytest tests/test_playwright_capture.py -m integration -v
```

## 开发

手动运行服务器进行测试：

```bash
uv run mitmproxy-mcp
```

运行单元测试（排除网络/浏览器集成测试）：

```bash
uv run pytest tests/ -q
```

运行集成测试：

```bash
# Playwright 浏览器捕获测试
uv run pytest tests/test_playwright_capture.py -m integration -v

# 所有 MCP 工具端到端测试
uv run pytest tests/test_all_tools.py -m integration -v
```

## 许可证

MIT
