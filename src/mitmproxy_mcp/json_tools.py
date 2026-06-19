"""Helpers for JSONPath extraction and large content preview."""

from __future__ import annotations

import base64
import json
from typing import Any

from jsonpath_ng import parse as jsonpath_parse
from jsonpath_ng.exceptions import JsonPathParserError


def extract_with_jsonpath(data: Any, paths: list[str]) -> dict[str, Any]:
    """Extract values from JSON data using JSONPath expressions.

    Args:
        data: Parsed JSON data (dict or list).
        paths: List of JSONPath expressions.

    Returns:
        A dictionary mapping each path to its extracted value(s).
        If a path matches exactly one value, the value is returned directly;
        otherwise a list of matches is returned.
    """
    result: dict[str, Any] = {}
    for path in paths:
        try:
            expr = jsonpath_parse(path)
            matches = [match.value for match in expr.find(data)]
            result[path] = matches[0] if len(matches) == 1 else matches
        except JsonPathParserError as e:
            result[path] = f"Error: invalid JSONPath expression - {e}"
        except Exception as e:  # pragma: no cover - defensive
            result[path] = f"Error extracting path: {e}"
    return result


def generate_json_structure(
    data: Any, max_depth: int = 2, current_depth: int = 0
) -> Any:
    """Generate a simplified structure preview of JSON content.

    Deep values are replaced with type indicators and collection sizes
    to keep the output short and readable for LLM context.
    """
    if current_depth >= max_depth:
        if isinstance(data, dict):
            return {"...": f"{len(data)} keys"}
        if isinstance(data, list):
            return f"[{len(data)} items]"
        return f"({type(data).__name__})"

    if isinstance(data, dict):
        return {
            key: generate_json_structure(value, max_depth, current_depth + 1)
            for key, value in data.items()
        }
    if isinstance(data, list):
        if not data:
            return []
        sample = generate_json_structure(data[0], max_depth, current_depth + 1)
        return [sample, f"... ({len(data) - 1} more items)"] if len(data) > 1 else [sample]
    return f"({type(data).__name__})"


def maybe_preview_content(
    content: str | None,
    content_encoding: str,
    max_size: int | None,
) -> dict[str, Any]:
    """Return preview information for content based on size limits.

    If the content is within the limit, it is returned unchanged.
    If it exceeds the limit and is JSON, a structure preview is returned.
    Otherwise the text is truncated with a note.
    """
    result: dict[str, Any] = {}
    if content is None or max_size is None or len(content) <= max_size:
        result["content"] = content
        return result

    # Attempt to obtain a UTF-8 text representation for preview.
    text_content = content
    if content_encoding == "base64":
        try:
            raw = base64.b64decode(content)
            # Treat content as binary if it contains null bytes.
            if b"\x00" in raw:
                raise UnicodeDecodeError("utf-8", raw, 0, 1, "binary data")
            text_content = raw.decode("utf-8")
        except Exception:
            result["content"] = None
            result["content_size"] = len(content)
            result["content_note"] = "Binary content too large to preview."
            return result

    # Try JSON structure preview first.
    try:
        json_data = json.loads(text_content)
        result["content"] = None
        result["content_preview"] = generate_json_structure(json_data)
        result["content_size"] = len(content)
        result["content_note"] = (
            "Content too large to display. Use flow_extract_json to get specific values."
        )
        return result
    except json.JSONDecodeError:
        pass

    # Fallback: truncate non-JSON text.
    result["content"] = text_content[:max_size] + " ...[truncated]"
    result["content_size"] = len(content)
    result["content_note"] = f"Content truncated to {max_size} bytes."
    return result
