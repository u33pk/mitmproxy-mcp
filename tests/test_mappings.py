"""Tests for mitmproxy_mcp.mappings."""

import tempfile
from pathlib import Path

import pytest

from mitmproxy_mcp.mappings import MapLocalRule, MapRemoteRule, MappingState


# ---------------------------------------------------------------------------
# MapLocalRule
# ---------------------------------------------------------------------------


def test_map_local_rule_to_spec_no_filter() -> None:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        path = f.name
    rule = MapLocalRule(id="r1", url_regex="https://example.com/api/.*", local_path=path)
    spec = rule.to_spec()
    assert spec.startswith("|")
    assert spec.endswith(f"|{path}")
    Path(path).unlink()


def test_map_local_rule_with_filter() -> None:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        path = f.name
    rule = MapLocalRule(
        id="r1",
        filter="~u example.com",
        url_regex="https://example.com/api/.*",
        local_path=path,
    )
    spec = rule.to_spec()
    parts = spec[1:].split(spec[0])
    assert len(parts) == 3
    assert parts[0] == "~u example.com"
    assert parts[1] == "https://example.com/api/.*"
    assert parts[2] == path
    Path(path).unlink()


def test_map_local_rule_invalid_regex() -> None:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    with pytest.raises(ValueError):
        MapLocalRule(id="r1", url_regex="[invalid", local_path=path)
    Path(path).unlink()


def test_map_local_rule_missing_file() -> None:
    with pytest.raises(ValueError):
        MapLocalRule(id="r1", url_regex="https://example.com/api/.*", local_path="/does/not/exist")


# ---------------------------------------------------------------------------
# MapRemoteRule
# ---------------------------------------------------------------------------


def test_map_remote_rule_to_spec_no_filter() -> None:
    rule = MapRemoteRule(
        id="r1",
        url_regex="https://example.com/api/.*",
        replacement="https://staging.example.com/api/",
    )
    spec = rule.to_spec()
    parts = spec[1:].split(spec[0])
    assert len(parts) == 2
    assert parts[0] == "https://example.com/api/.*"
    assert parts[1] == "https://staging.example.com/api/"


def test_map_remote_rule_invalid_regex() -> None:
    with pytest.raises(ValueError):
        MapRemoteRule(id="r1", url_regex="[invalid", replacement="https://x.com/")


# ---------------------------------------------------------------------------
# MappingState
# ---------------------------------------------------------------------------


def test_add_and_list_local_rules() -> None:
    state = MappingState()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    rule = MapLocalRule(id="r1", url_regex="https://example.com/.*", local_path=path)
    state.add_local_rule(rule)
    assert len(state.list_local_rules()) == 1
    assert state.local_specs()[0] == rule.to_spec()
    Path(path).unlink()


def test_local_specs_only_enabled() -> None:
    state = MappingState()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    state.add_local_rule(
        MapLocalRule(id="r1", enabled=False, url_regex="https://a.com/.*", local_path=path)
    )
    state.add_local_rule(
        MapLocalRule(id="r2", enabled=True, url_regex="https://b.com/.*", local_path=path)
    )
    assert len(state.local_specs()) == 1
    assert "https://b.com/" in state.local_specs()[0]
    Path(path).unlink()


def test_delete_local_rule() -> None:
    state = MappingState()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    state.add_local_rule(MapLocalRule(id="r1", url_regex="https://a.com/.*", local_path=path))
    assert state.delete_local_rule("r1") is True
    assert state.delete_local_rule("r1") is False
    Path(path).unlink()


def test_remote_rules_management() -> None:
    state = MappingState()
    rule = MapRemoteRule(id="r1", url_regex="https://a.com/.*", replacement="https://b.com/")
    state.add_remote_rule(rule)
    assert len(state.list_remote_rules()) == 1
    assert state.remote_specs()[0] == rule.to_spec()
    assert state.delete_remote_rule("r1") is True
    assert len(state.list_remote_rules()) == 0
