"""Tests for mitmproxy_mcp.json_tools."""

from __future__ import annotations

import json

import pytest

from mitmproxy_mcp.json_tools import (
    extract_with_jsonpath,
    generate_json_structure,
    maybe_preview_content,
)


def test_extract_with_jsonpath_nested_dict() -> None:
    data = {"user": {"name": "Alice", "age": 30}, "items": [1, 2, 3]}
    result = extract_with_jsonpath(data, ["$.user.name", "$.items[0]"])
    assert result["$.user.name"] == "Alice"
    assert result["$.items[0]"] == 1


def test_extract_with_jsonpath_multiple_matches() -> None:
    data = {"users": [{"name": "Alice"}, {"name": "Bob"}]}
    result = extract_with_jsonpath(data, ["$.users[*].name"])
    assert result["$.users[*].name"] == ["Alice", "Bob"]


def test_extract_with_jsonpath_invalid_expression() -> None:
    data = {"a": 1}
    result = extract_with_jsonpath(data, ["$.a", "this is not valid"])
    assert result["$.a"] == 1
    assert "Error" in result["this is not valid"]


def test_generate_json_structure_dict() -> None:
    data = {"user": {"name": "Alice", "age": 30}, "tags": ["a", "b", "c"]}
    preview = generate_json_structure(data, max_depth=1)
    assert preview == {"user": {"...": "2 keys"}, "tags": "[3 items]"}


def test_generate_json_structure_list() -> None:
    data = [{"id": 1, "name": "x"}, {"id": 2, "name": "y"}]
    preview = generate_json_structure(data, max_depth=2)
    assert preview[0] == {"id": "(int)", "name": "(str)"}
    assert "1 more items" in preview[1]


def test_generate_json_structure_scalar() -> None:
    assert generate_json_structure("hello") == "(str)"
    assert generate_json_structure(42) == "(int)"


def test_maybe_preview_content_within_limit() -> None:
    result = maybe_preview_content("hello", "text", 100)
    assert result["content"] == "hello"
    assert "content_preview" not in result
    assert "content_note" not in result


def test_maybe_preview_content_no_limit() -> None:
    result = maybe_preview_content("hello", "text", None)
    assert result["content"] == "hello"


def test_maybe_preview_content_json_preview() -> None:
    data = {"users": [{"name": "Alice"}, {"name": "Bob"}], "count": 2}
    content = json.dumps(data)
    result = maybe_preview_content(content, "text", 20)
    assert result["content"] is None
    assert "content_preview" in result
    assert "content_note" in result
    assert result["content_size"] == len(content)


def test_maybe_preview_content_text_truncation() -> None:
    content = "a" * 100
    result = maybe_preview_content(content, "text", 20)
    assert result["content"] == "a" * 20 + " ...[truncated]"
    assert result["content_size"] == 100
    assert "truncated" in result["content_note"]


def test_maybe_preview_content_none() -> None:
    result = maybe_preview_content(None, "text", 100)
    assert result["content"] is None


def test_maybe_preview_content_base64_json() -> None:
    data = {"items": [1, 2, 3]}
    text = json.dumps(data)
    encoded = __import__("base64").b64encode(text.encode()).decode()
    result = maybe_preview_content(encoded, "base64", 10)
    assert result["content"] is None
    assert "content_preview" in result


def test_maybe_preview_content_base64_binary() -> None:
    encoded = __import__("base64").b64encode(b"\x00\x01\x02").decode()
    result = maybe_preview_content(encoded, "base64", 2)
    assert result["content"] is None
    assert "Binary content" in result["content_note"]
