"""URL mapping rules for map_local and map_remote."""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MapLocalRule(BaseModel):
    """A rule that maps matching URLs to a local file or directory."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    filter: str = ""
    url_regex: str = Field(..., min_length=1)
    local_path: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def _validate(self) -> "MapLocalRule":
        try:
            re.compile(self.url_regex)
        except re.error as e:
            raise ValueError(f"Invalid url_regex: {e}") from e
        path = Path(self.local_path).expanduser()
        if not path.exists():
            raise ValueError(f"Local path does not exist: {self.local_path}")
        return self

    def to_spec(self) -> str:
        sep = self._choose_separator()
        filter_part = f"{self.filter}{sep}" if self.filter else ""
        return f"{sep}{filter_part}{self.url_regex}{sep}{self.local_path}"

    def _choose_separator(self) -> str:
        candidates = "|#~^`$@"
        for sep in candidates:
            if sep not in self.filter and sep not in self.url_regex and sep not in self.local_path:
                return sep
        raise ValueError("Cannot find a suitable separator for map_local spec")


class MapRemoteRule(BaseModel):
    """A rule that rewrites matching URLs to another URL."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    filter: str = ""
    url_regex: str = Field(..., min_length=1)
    replacement: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def _validate(self) -> "MapRemoteRule":
        try:
            re.compile(self.url_regex)
        except re.error as e:
            raise ValueError(f"Invalid url_regex: {e}") from e
        return self

    def to_spec(self) -> str:
        sep = self._choose_separator()
        filter_part = f"{self.filter}{sep}" if self.filter else ""
        return f"{sep}{filter_part}{self.url_regex}{sep}{self.replacement}"

    def _choose_separator(self) -> str:
        candidates = "|#~^`$@"
        for sep in candidates:
            if sep not in self.filter and sep not in self.url_regex and sep not in self.replacement:
                return sep
        raise ValueError("Cannot find a suitable separator for map_remote spec")


class MappingState:
    """Thread-safe storage for map_local and map_remote rules."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._local_rules: list[MapLocalRule] = []
        self._remote_rules: list[MapRemoteRule] = []

    # ------------------------------------------------------------------
    # map_local
    # ------------------------------------------------------------------

    def list_local_rules(self) -> list[MapLocalRule]:
        with self._lock:
            return list(self._local_rules)

    def add_local_rule(self, rule: MapLocalRule) -> None:
        with self._lock:
            self._local_rules = [r for r in self._local_rules if r.id != rule.id]
            self._local_rules.append(rule)

    def delete_local_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._local_rules)
            self._local_rules = [r for r in self._local_rules if r.id != rule_id]
            return len(self._local_rules) < before

    def clear_local_rules(self) -> int:
        with self._lock:
            count = len(self._local_rules)
            self._local_rules.clear()
            return count

    def local_specs(self) -> list[str]:
        with self._lock:
            return [r.to_spec() for r in self._local_rules if r.enabled]

    # ------------------------------------------------------------------
    # map_remote
    # ------------------------------------------------------------------

    def list_remote_rules(self) -> list[MapRemoteRule]:
        with self._lock:
            return list(self._remote_rules)

    def add_remote_rule(self, rule: MapRemoteRule) -> None:
        with self._lock:
            self._remote_rules = [r for r in self._remote_rules if r.id != rule.id]
            self._remote_rules.append(rule)

    def delete_remote_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._remote_rules)
            self._remote_rules = [r for r in self._remote_rules if r.id != rule_id]
            return len(self._remote_rules) < before

    def clear_remote_rules(self) -> int:
        with self._lock:
            count = len(self._remote_rules)
            self._remote_rules.clear()
            return count

    def remote_specs(self) -> list[str]:
        with self._lock:
            return [r.to_spec() for r in self._remote_rules if r.enabled]
