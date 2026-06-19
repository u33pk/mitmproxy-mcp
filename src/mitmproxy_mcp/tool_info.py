"""Progressive tool documentation queried via the tool_info MCP tool."""

from __future__ import annotations

from typing import Any


CommandInfo = dict[str, Any]
ToolInfo = dict[str, Any]


TOOL_INFO: dict[str, ToolInfo] = {
    "proxy_ctl": {
        "summary": "Start, stop and inspect the mitmproxy capture proxy.",
        "commands": {
            "start": {
                "description": "Start the capture proxy in a background thread.",
                "required": [],
                "optional": [
                    "host (str, default 127.0.0.1)",
                    "port (int, default 8080)",
                    "capture_filter (str, optional mitmproxy flowfilter expression)",
                    "ssl_insecure (bool, default False)",
                    "upstream_proxy (str, e.g. http://host:port)",
                    "extra_options (dict, passed to mitmproxy options.Options)",
                ],
                "example": {"cmd": "start", "port": 8080},
            },
            "stop": {
                "description": "Stop the running proxy.",
                "required": [],
                "optional": [],
                "example": {"cmd": "stop"},
            },
            "status": {
                "description": "Return proxy running state, listen address and captured flow count.",
                "required": [],
                "optional": [],
                "example": {"cmd": "status"},
            },
            "wireguard_config": {
                "description": "Return the WireGuard client configuration when the proxy was started in WireGuard mode. The returned INI can be imported into iOS, Android, macOS or Windows WireGuard clients. Certificate trust is still required for HTTPS/HTTP3 decryption.",
                "required": [],
                "optional": [],
                "example": {"cmd": "wireguard_config"},
            },
            "list_options": {
                "description": "List mitmproxy-native options available via extra_options.",
                "required": [],
                "optional": [],
                "example": {"cmd": "list_options"},
            },
            "clear_all": {
                "description": "Clear all flows, rules, capture rules and mappings. Optionally stop the proxy.",
                "required": [],
                "optional": ["stop_proxy (bool, default False)"],
                "example": {"cmd": "clear_all", "stop_proxy": False},
            },
        },
    },
    "flow_ctl": {
        "summary": "Manage and inspect captured HTTP/WebSocket flows.",
        "commands": {
            "list": {
                "description": "List captured flows with optional filters and pagination.",
                "required": [],
                "optional": [
                    "offset (int, default 0)",
                    "limit (int, default 50)",
                    "host (str, glob)",
                    "method (str)",
                    "status (int)",
                    "search (str, regex)",
                    "websocket_only (bool, default False)",
                ],
                "example": {"cmd": "list", "limit": 20},
            },
            "get": {
                "description": "Get full details of a single flow by flow_id.",
                "required": ["flow_id"],
                "optional": [
                    "include_content (bool, default True)",
                    "max_content_size (int, truncate/preview large bodies)",
                ],
                "example": {"cmd": "get", "flow_id": 1, "max_content_size": 4096},
            },
            "delete": {
                "description": "Delete a single flow from memory.",
                "required": ["flow_id"],
                "optional": [],
                "example": {"cmd": "delete", "flow_id": 1},
            },
            "clear": {
                "description": "Clear all in-memory flows.",
                "required": [],
                "optional": ["stop_proxy (bool, default False)"],
                "example": {"cmd": "clear"},
            },
            "load": {
                "description": "Load flows from a .mitm file.",
                "required": ["path"],
                "optional": [],
                "example": {"cmd": "load", "path": "/tmp/flows.mitm"},
            },
            "save": {
                "description": "Save current flows to a .mitm file.",
                "required": ["path"],
                "optional": [],
                "example": {"cmd": "save", "path": "/tmp/flows.mitm"},
            },
            "extract_json": {
                "description": "Extract JSONPath values from request or response body.",
                "required": ["flow_id", "target", "jsonpath"],
                "optional": [],
                "example": {
                    "cmd": "extract_json",
                    "flow_id": 1,
                    "target": "response",
                    "jsonpath": ["$.data[0].id"],
                },
            },
        },
    },
    "flow_action": {
        "summary": "Replay, resume, kill, update, create or send HTTP/WebSocket flows.",
        "commands": {
            "replay": {
                "description": "Replay a captured flow via mitmproxy replay.client.",
                "required": ["flow_id"],
                "optional": ["use_modified (bool, default True)"],
                "example": {"action": "replay", "flow_id": 1},
            },
            "resume": {
                "description": "Resume an intercepted (breakpoint-paused) flow.",
                "required": ["flow_id"],
                "optional": [],
                "example": {"action": "resume", "flow_id": 1},
            },
            "kill": {
                "description": "Kill a running or intercepted flow.",
                "required": ["flow_id"],
                "optional": [],
                "example": {"action": "kill", "flow_id": 1},
            },
            "update": {
                "description": "Modify request/response fields and metadata of a captured flow.",
                "required": ["flow_id"],
                "optional": [
                    "request_method", "request_path", "request_headers", "request_body", "request_body_encoding",
                    "response_status", "response_reason", "response_headers", "response_body", "response_body_encoding",
                    "comment", "marked", "tags",
                ],
                "example": {
                    "action": "update",
                    "flow_id": 1,
                    "response_status": 200,
                    "comment": "modified",
                },
            },
            "create": {
                "description": "Create a new request flow without sending.",
                "required": ["method", "url"],
                "optional": ["headers", "body", "encoding (text|base64, default text)", "comment"],
                "example": {"action": "create", "method": "GET", "url": "http://example.com/"},
            },
            "send": {
                "description": "Send a new HTTP request via mitmproxy replay.client.",
                "required": ["method", "url"],
                "optional": ["headers", "body", "encoding (text|base64, default text)"],
                "example": {"action": "send", "method": "POST", "url": "http://example.com/api", "body": "{}"},
            },
        },
    },
    "rule_ctl": {
        "summary": "Manage automatic request/response modification rules.",
        "commands": {
            "list": {
                "description": "List all automatic rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "list"},
            },
            "add": {
                "description": "Add or replace an automatic rule. Existing rule with same id is overwritten.",
                "required": ["rule"],
                "optional": [],
                "example": {
                    "cmd": "add",
                    "rule": {
                        "id": "mock",
                        "filter": "~u example.com/api",
                        "phase": "response",
                        "actions": [{"type": "set_status", "status_code": 200}],
                    },
                },
            },
            "delete": {
                "description": "Delete a rule by id.",
                "required": ["rule_id"],
                "optional": [],
                "example": {"cmd": "delete", "rule_id": "mock"},
            },
            "clear": {
                "description": "Delete all automatic rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "clear"},
            },
        },
    },
    "capture_rule_ctl": {
        "summary": "Manage include/exclude capture rules.",
        "commands": {
            "list": {
                "description": "List all capture rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "list"},
            },
            "add": {
                "description": "Add or replace a capture rule. Existing rule with same id is overwritten.",
                "required": ["rule"],
                "optional": [],
                "example": {
                    "cmd": "add",
                    "rule": {"id": "api", "filter": "~u api.example.com", "action": "include"},
                },
            },
            "delete": {
                "description": "Delete a capture rule by id.",
                "required": ["rule_id"],
                "optional": [],
                "example": {"cmd": "delete", "rule_id": "api"},
            },
            "clear": {
                "description": "Delete all capture rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "clear"},
            },
        },
    },
    "mock_server_ctl": {
        "summary": "Control server-side mock/playback from captured flows.",
        "commands": {
            "start": {
                "description": "Start mock server. If flow_ids omitted, all stored flows are used.",
                "required": [],
                "optional": [
                    "flow_ids (list[int])",
                    "ignore_host (bool)",
                    "ignore_port (bool)",
                    "ignore_params (list[str])",
                    "ignore_content (bool)",
                    "extra (str, default forward)",
                ],
                "example": {"cmd": "start", "flow_ids": [1, 2]},
            },
            "add": {
                "description": "Add more captured flows to the running mock server.",
                "required": ["flow_ids"],
                "optional": [],
                "example": {"cmd": "add", "flow_ids": [3]},
            },
            "stop": {
                "description": "Stop the mock server and clear recorded responses.",
                "required": [],
                "optional": [],
                "example": {"cmd": "stop"},
            },
            "status": {
                "description": "Show the number of flows loaded into the mock server.",
                "required": [],
                "optional": [],
                "example": {"cmd": "status"},
            },
        },
    },
    "map_local_ctl": {
        "summary": "Map matching URLs to local files or directories.",
        "commands": {
            "list": {
                "description": "List all map_local rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "list"},
            },
            "add": {
                "description": "Add or replace a map_local rule. local_path must exist.",
                "required": ["rule"],
                "optional": [],
                "example": {
                    "cmd": "add",
                    "rule": {
                        "id": "mock",
                        "filter": "~u example.com/api/data",
                        "url_regex": "https://example.com/api/data",
                        "local_path": "/tmp/mock.json",
                    },
                },
            },
            "delete": {
                "description": "Delete a rule by id.",
                "required": ["rule_id"],
                "optional": [],
                "example": {"cmd": "delete", "rule_id": "mock"},
            },
            "clear": {
                "description": "Delete all map_local rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "clear"},
            },
        },
    },
    "map_remote_ctl": {
        "summary": "Rewrite matching URLs to another remote URL.",
        "commands": {
            "list": {
                "description": "List all map_remote rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "list"},
            },
            "add": {
                "description": "Add or replace a map_remote rule.",
                "required": ["rule"],
                "optional": [],
                "example": {
                    "cmd": "add",
                    "rule": {
                        "id": "staging",
                        "filter": "~u example.com/api",
                        "url_regex": "https://example.com/api(.*)",
                        "replacement": "https://staging.example.com/api$1",
                    },
                },
            },
            "delete": {
                "description": "Delete a rule by id.",
                "required": ["rule_id"],
                "optional": [],
                "example": {"cmd": "delete", "rule_id": "staging"},
            },
            "clear": {
                "description": "Delete all map_remote rules.",
                "required": [],
                "optional": [],
                "example": {"cmd": "clear"},
            },
        },
    },
    "tool_info": {
        "summary": "Query detailed documentation for any MCP tool.",
        "commands": {
            "": {
                "description": "Return full documentation for a tool, or a specific command if cmd is provided.",
                "required": ["tool_name"],
                "optional": ["cmd"],
                "example": {"tool_name": "proxy_ctl", "cmd": "start"},
            },
        },
    },
}


def get_tool_info(tool_name: str, cmd: str | None = None) -> dict[str, Any]:
    """Return documentation for a tool. If cmd is provided, return only that command."""
    info = TOOL_INFO.get(tool_name)
    if info is None:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    if cmd is None:
        return {"success": True, "tool": tool_name, "doc": info}

    commands = info.get("commands", {})
    if cmd not in commands:
        return {
            "success": False,
            "error": f"Unknown command '{cmd}' for tool '{tool_name}'",
            "available_commands": list(commands.keys()),
        }
    return {"success": True, "tool": tool_name, "cmd": cmd, "doc": commands[cmd]}
