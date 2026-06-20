"""WebSocket message modification rules."""

from __future__ import annotations

import base64
import logging
import re
import threading
from typing import Any, Literal

from mitmproxy import flowfilter
from mitmproxy import http
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

logger = logging.getLogger(__name__)


class WebSocketRule(BaseModel):
    """A rule that modifies or drops WebSocket messages in real time."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    flow_filter: str | None = None
    direction: Literal["both", "client", "server"] = "both"
    message_filter: str | None = None
    action: Literal["drop", "replace", "replace_regex"]
    replacement: str | None = None
    replacement_regex: str | None = None

    _compiled_flow_filter: flowfilter.TFilter | None = PrivateAttr(default=None)
    _compiled_message_filter: re.Pattern[str] | None = PrivateAttr(default=None)

    def model_post_init(self, __context: Any) -> None:
        if self.flow_filter:
            try:
                self._compiled_flow_filter = flowfilter.parse(self.flow_filter)
            except ValueError as e:
                raise ValueError(
                    f"Invalid flow filter expression '{self.flow_filter}': {e}"
                ) from e
        if self.message_filter:
            try:
                self._compiled_message_filter = re.compile(self.message_filter)
            except re.error as e:
                raise ValueError(
                    f"Invalid message filter regex '{self.message_filter}': {e}"
                ) from e

    @model_validator(mode="after")
    def _check_required_fields(self) -> "WebSocketRule":
        if self.action in ("replace", "replace_regex") and self.replacement is None:
            raise ValueError(f"Action '{self.action}' requires 'replacement'")
        if self.action == "replace_regex" and self.replacement_regex is None:
            raise ValueError("Action 'replace_regex' requires 'replacement_regex'")
        return self

    def _matches_flow(self, flow: http.HTTPFlow) -> bool:
        if not self.flow_filter or self._compiled_flow_filter is None:
            return True
        try:
            return bool(self._compiled_flow_filter(flow))
        except Exception as e:
            logger.warning(f"WebSocket rule '{self.id}' flow filter failed: {e}")
            return False

    def _matches_direction(self, from_client: bool) -> bool:
        if self.direction == "both":
            return True
        if self.direction == "client":
            return from_client
        return not from_client

    def _matches_message(self, msg: Any) -> bool:
        if not self.message_filter or self._compiled_message_filter is None:
            return True
        try:
            if msg.is_text:
                text = msg.content.decode("utf-8", errors="replace")
            else:
                text = base64.b64encode(msg.content).decode("ascii")
            return bool(self._compiled_message_filter.search(text))
        except Exception as e:
            logger.warning(f"WebSocket rule '{self.id}' message filter failed: {e}")
            return False

    def apply(self, flow: http.HTTPFlow, msg: Any) -> bool:
        """Apply the rule to a WebSocket message. Returns True if the message was dropped."""
        if not self.enabled:
            return False
        if not self._matches_flow(flow):
            return False
        if not self._matches_direction(msg.from_client):
            return False
        if not self._matches_message(msg):
            return False

        try:
            return self._apply_action(msg)
        except Exception as e:
            logger.warning(f"WebSocket rule '{self.id}' action failed: {e}")
            return False

    def _apply_action(self, msg: Any) -> bool:
        if self.action == "drop":
            msg.drop()
            return True

        if self.action == "replace":
            if msg.is_text:
                msg.text = self.replacement or ""
            else:
                msg.content = base64.b64decode(self.replacement or "")
            return False

        if self.action == "replace_regex":
            if msg.is_text:
                new_text = re.sub(
                    self.replacement_regex or "",
                    self.replacement or "",
                    msg.text,
                )
                msg.text = new_text
            else:
                original = base64.b64encode(msg.content).decode("ascii")
                new_text = re.sub(
                    self.replacement_regex or "",
                    self.replacement or "",
                    original,
                )
                msg.content = base64.b64decode(new_text)
            return False

        return False


class WebSocketRulesAddon:
    """mitmproxy addon that applies WebSocket message modification rules."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: list[WebSocketRule] = []

    # ------------------------------------------------------------------
    # Rule management (called from the MCP tool thread)
    # ------------------------------------------------------------------

    def list_rules(self) -> list[WebSocketRule]:
        with self._lock:
            return list(self._rules)

    def add_rule(self, rule: WebSocketRule) -> None:
        with self._lock:
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._rules.append(rule)

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

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if flow.websocket is None or not flow.websocket.messages:
            return

        with self._lock:
            rules = list(self._rules)

        msg = flow.websocket.messages[-1]
        for rule in rules:
            dropped = rule.apply(flow, msg)
            if dropped:
                break
