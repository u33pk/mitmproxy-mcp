"""Automatic rule engine for intercepting and modifying HTTP flows."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import threading
from typing import Any, Literal

from mitmproxy import flowfilter
from mitmproxy import http
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

logger = logging.getLogger(__name__)


class Action(BaseModel):
    """A single action executed when a rule matches."""

    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "set_header",
        "remove_header",
        "set_body",
        "replace_body",
        "set_status",
        "set_path",
        "set_method",
        "delay",
        "kill",
        "intercept",
        "resume",
        "mark",
        "comment",
        "tag",
    ]

    # Common contextual fields
    target: Literal["request", "response"] | None = None

    # Header actions
    name: str | None = None
    value: str | None = None

    # Body actions
    content: str | None = None
    encoding: Literal["text", "base64"] = "text"
    pattern: str | None = None
    replacement: str | None = None

    # Response status
    status_code: int | None = None
    reason: str | None = None

    # Request line
    path: str | None = None
    method: str | None = None

    # Delay
    seconds: float | None = None

    # Metadata
    marker: str | None = None
    comment: str | None = None
    tags: list[str] | None = None

    @model_validator(mode="after")
    def _check_required_fields(self) -> "Action":
        t = self.type

        if t in ("set_header", "remove_header"):
            if self.target is None:
                raise ValueError(f"Action '{t}' requires 'target'")
            if not self.name:
                raise ValueError(f"Action '{t}' requires 'name'")

        if t == "set_header" and self.value is None:
            raise ValueError("Action 'set_header' requires 'value'")

        if t == "set_body":
            if self.target is None:
                raise ValueError("Action 'set_body' requires 'target'")
            if self.content is None:
                raise ValueError("Action 'set_body' requires 'content'")

        if t == "replace_body":
            if self.target is None:
                raise ValueError("Action 'replace_body' requires 'target'")
            if self.pattern is None or self.replacement is None:
                raise ValueError("Action 'replace_body' requires 'pattern' and 'replacement'")

        if t == "set_status":
            if self.status_code is None:
                raise ValueError("Action 'set_status' requires 'status_code'")

        if t == "set_path" and self.path is None:
            raise ValueError("Action 'set_path' requires 'path'")

        if t == "set_method" and self.method is None:
            raise ValueError("Action 'set_method' requires 'method'")

        if t == "delay" and self.seconds is None:
            raise ValueError("Action 'delay' requires 'seconds'")

        if t == "mark" and self.marker is None:
            raise ValueError("Action 'mark' requires 'marker'")

        if t == "comment" and self.comment is None:
            raise ValueError("Action 'comment' requires 'comment'")

        if t == "tag" and self.tags is None:
            raise ValueError("Action 'tag' requires 'tags'")

        return self


class Rule(BaseModel):
    """A rule that matches flows and applies actions automatically."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    phase: Literal["request", "response", "both"] = "both"
    filter: str = Field(..., min_length=1)
    actions: list[Action] = Field(default_factory=list)

    _compiled_filter: flowfilter.TFilter | None = PrivateAttr(default=None)

    def model_post_init(self, __context: Any) -> None:
        try:
            self._compiled_filter = flowfilter.parse(self.filter)
        except ValueError as e:
            raise ValueError(f"Invalid filter expression '{self.filter}': {e}") from e

    def matches(self, flow: http.HTTPFlow, phase: str) -> bool:
        if not self.enabled:
            return False
        if self.phase != "both" and self.phase != phase:
            return False
        if self._compiled_filter is None:
            return False
        try:
            return bool(self._compiled_filter(flow))
        except Exception as e:
            logger.warning(f"Rule '{self.id}' filter evaluation failed: {e}")
            return False


def _decode_content(content: str, encoding: Literal["text", "base64"]) -> bytes:
    if encoding == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8")


class RulesAddon:
    """mitmproxy addon that applies user-defined rules to live flows."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: list[Rule] = []

    # ------------------------------------------------------------------
    # Rule management (called from the MCP tool thread)
    # ------------------------------------------------------------------

    def list_rules(self) -> list[Rule]:
        with self._lock:
            return list(self._rules)

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            # Replace existing rule with same id.
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._rules.append(rule)

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> Rule | None:
        with self._lock:
            for idx, existing in enumerate(self._rules):
                if existing.id == rule_id:
                    data = existing.model_dump()
                    data.update(updates)
                    # Re-validate filter by creating a new Rule.
                    new_rule = Rule(**data)
                    self._rules[idx] = new_rule
                    return new_rule
        return None

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            return len(self._rules) < before

    def clear_rules(self) -> int:
        with self._lock:
            count = len(self._rules)
            self._rules.clear()
            return count

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    async def request(self, flow: http.HTTPFlow) -> None:
        await self._process(flow, "request")

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._process(flow, "response")

    async def _process(self, flow: http.HTTPFlow, phase: str) -> None:
        with self._lock:
            rules = list(self._rules)

        applied_rule_ids: list[str] = []
        for rule in rules:
            if not rule.matches(flow, phase):
                continue
            try:
                await self._apply_actions(flow, rule.actions)
                applied_rule_ids.append(rule.id)
            except Exception as e:
                logger.warning(f"Rule '{rule.id}' actions failed: {e}")

        if applied_rule_ids:
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata.setdefault("mitmproxy_mcp_rules_applied", []).extend(
                applied_rule_ids
            )

    async def _apply_actions(
        self, flow: http.HTTPFlow, actions: list[Action]
    ) -> None:
        for action in actions:
            await self._apply_action(flow, action)

    async def _apply_action(self, flow: http.HTTPFlow, action: Action) -> None:
        t = action.type

        if t == "set_header":
            target = self._get_message(flow, action.target)
            if target is not None:
                target.headers[action.name] = action.value
            return

        if t == "remove_header":
            target = self._get_message(flow, action.target)
            if target is not None:
                target.headers.pop(action.name, None)
            return

        if t == "set_body":
            target = self._get_message(flow, action.target)
            if target is not None:
                target.content = _decode_content(action.content, action.encoding)
            return

        if t == "replace_body":
            target = self._get_message(flow, action.target)
            if target is not None:
                pattern = action.pattern.encode("utf-8")
                replacement = action.replacement.encode("utf-8")
                target.content = re.sub(
                    pattern, replacement, target.content, flags=re.DOTALL
                )
            return

        if t == "set_status":
            if flow.response is None:
                flow.response = http.Response.make(
                    status_code=action.status_code,
                    content=b"",
                )
            flow.response.status_code = action.status_code
            if action.reason is not None:
                flow.response.reason = action.reason
            return

        if t == "set_path":
            flow.request.path = action.path
            return

        if t == "set_method":
            flow.request.method = action.method
            return

        if t == "delay":
            await asyncio.sleep(action.seconds)
            return

        if t == "kill":
            if flow.killable:
                flow.kill()
            return

        if t == "intercept":
            flow.intercept()
            return

        if t == "resume":
            flow.resume()
            return

        if t == "mark":
            flow.marked = action.marker
            return

        if t == "comment":
            flow.comment = action.comment
            return

        if t == "tag":
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata["tags"] = action.tags
            return

    @staticmethod
    def _get_message(
        flow: http.HTTPFlow, target: Literal["request", "response"] | None
    ) -> http.Request | http.Response | None:
        if target == "request":
            return flow.request
        if target == "response":
            return flow.response
        return None
