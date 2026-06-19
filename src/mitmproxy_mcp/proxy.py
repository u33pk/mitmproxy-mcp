"""mitmproxy integration: CaptureAddon and ProxyManager."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Literal

from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import options
from mitmproxy.addonmanager import Loader
from mitmproxy.tools.dump import DumpMaster
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from mitmproxy_mcp.mappings import MapLocalRule, MapRemoteRule, MappingState
from mitmproxy_mcp.rules import Rule, RulesAddon
from mitmproxy_mcp.store import FlowStore

logger = logging.getLogger(__name__)


class CaptureRule(BaseModel):
    """A rule that decides whether a flow should be captured."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    filter: str = Field(..., min_length=1)
    action: Literal["include", "exclude"]

    _compiled_filter: flowfilter.TFilter | None = PrivateAttr(default=None)

    def model_post_init(self, __context: Any) -> None:
        try:
            self._compiled_filter = flowfilter.parse(self.filter)
        except ValueError as e:
            raise ValueError(f"Invalid filter expression '{self.filter}': {e}") from e

    def matches(self, flow: http.HTTPFlow) -> bool:
        if not self.enabled or self._compiled_filter is None:
            return False
        try:
            return bool(self._compiled_filter(flow))
        except Exception as e:
            logger.warning(f"Capture rule '{self.id}' filter evaluation failed: {e}")
            return False


class CaptureAddon:
    """An addon that captures HTTP flows into a FlowStore."""

    def __init__(
        self,
        store: FlowStore,
        capture_filter: str | None = None,
        capture_rules: list[CaptureRule] | None = None,
    ) -> None:
        self.store = store
        self.capture_filter = capture_filter
        self._filter: flowfilter.TFilter | None = None
        self._lock = threading.RLock()
        self._capture_rules: list[CaptureRule] = []
        self._compile_filter()
        if capture_rules:
            self.set_rules(capture_rules)

    def load(self, loader: Loader) -> None:
        self._compile_filter()

    def _compile_filter(self) -> None:
        if self.capture_filter:
            try:
                self._filter = flowfilter.parse(self.capture_filter)
            except ValueError as e:
                logger.warning(f"Invalid capture filter '{self.capture_filter}': {e}")
        else:
            self._filter = None

    def set_capture_filter(self, capture_filter: str | None) -> None:
        """Update the base capture filter at runtime."""
        self.capture_filter = capture_filter
        self._compile_filter()

    # ------------------------------------------------------------------
    # Rule management (called from the MCP tool thread)
    # ------------------------------------------------------------------

    def list_rules(self) -> list[CaptureRule]:
        with self._lock:
            return list(self._capture_rules)

    def set_rules(self, rules: list[CaptureRule]) -> None:
        with self._lock:
            self._capture_rules = list(rules)

    def add_rule(self, rule: CaptureRule) -> None:
        with self._lock:
            self._capture_rules = [r for r in self._capture_rules if r.id != rule.id]
            self._capture_rules.append(rule)

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> CaptureRule | None:
        with self._lock:
            for idx, existing in enumerate(self._capture_rules):
                if existing.id == rule_id:
                    data = existing.model_dump()
                    data.update(updates)
                    new_rule = CaptureRule(**data)
                    self._capture_rules[idx] = new_rule
                    return new_rule
        return None

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._capture_rules)
            self._capture_rules = [r for r in self._capture_rules if r.id != rule_id]
            return len(self._capture_rules) < before

    def clear_rules(self) -> int:
        with self._lock:
            count = len(self._capture_rules)
            self._capture_rules.clear()
            return count

    # ------------------------------------------------------------------
    # Capture decision
    # ------------------------------------------------------------------

    def should_capture(self, flow: http.HTTPFlow) -> bool:
        with self._lock:
            base_filter = self._filter
            rules = list(self._capture_rules)

        if base_filter is not None and not base_filter(flow):
            return False

        if not rules:
            return True

        include_rules = [r for r in rules if r.action == "include" and r.enabled]
        exclude_rules = [r for r in rules if r.action == "exclude" and r.enabled]

        for rule in exclude_rules:
            if rule.matches(flow):
                return False

        if include_rules:
            for rule in include_rules:
                if rule.matches(flow):
                    return True
            return False

        return True

    def response(self, flow: http.HTTPFlow) -> None:
        if self.should_capture(flow):
            self.store.add(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        # Also capture failed flows so errors are visible.
        if self.should_capture(flow):
            self.store.add(flow)

    # ------------------------------------------------------------------
    # WebSocket hooks
    # ------------------------------------------------------------------

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        # The HTTP upgrade response is already captured by `response`, but
        # ensure the WebSocket flow is tracked in case filters behave
        # differently at upgrade time.
        if self.should_capture(flow):
            self.store.add(flow)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # Messages are appended directly to flow.websocket.messages on the
        # same object stored in FlowStore, so no extra bookkeeping is needed.
        if flow.websocket and flow.metadata:
            flow.metadata["websocket_message_count"] = len(flow.websocket.messages)

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        # Connection close state is stored on flow.websocket automatically.
        pass


class ProxyManager:
    """Manages a mitmproxy DumpMaster running in a background thread."""

    def __init__(self, store: FlowStore) -> None:
        self.store = store
        self._master: DumpMaster | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._lock = threading.RLock()
        self._options: dict[str, Any] = {}
        self.capture_addon = CaptureAddon(self.store)
        self.rules_addon = RulesAddon()
        self.mapping_state = MappingState()

    def _run_proxy(
        self,
        host: str,
        port: int,
        capture_filter: str | None,
        ssl_insecure: bool,
        upstream_proxy: str | None,
        extra_options: dict[str, Any] | None,
    ) -> None:
        """Thread target that creates and runs the mitmproxy event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        opts_kwargs: dict[str, Any] = {
            "listen_host": host,
            "listen_port": port,
            "ssl_insecure": ssl_insecure,
        }
        if upstream_proxy:
            opts_kwargs["mode"] = [f"upstream:{upstream_proxy}"]
        if extra_options:
            opts_kwargs.update(extra_options)
        opts = options.Options(**opts_kwargs)

        async def _setup() -> DumpMaster:
            # DumpMaster needs a running event loop during construction.
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.capture_addon.set_capture_filter(capture_filter)
            master.addons.add(self.capture_addon)
            master.addons.add(self.rules_addon)
            # Sync any mappings that were configured before the proxy started.
            self._sync_mapping_options(master)
            return master

        # with_termlog=False and with_dumper=False keep stdout clean for stdio MCP.
        self._master = self._loop.run_until_complete(_setup())
        self._ready.set()
        self._loop.run_until_complete(self._master.run())

    @property
    def is_running(self) -> bool:
        with self._lock:
            return (
                self._master is not None
                and self._thread is not None
                and self._thread.is_alive()
            )

    @property
    def listen_host(self) -> str | None:
        return self._options.get("host")

    @property
    def listen_port(self) -> int | None:
        return self._options.get("port")

    @property
    def capture_filter(self) -> str | None:
        return self._options.get("capture_filter")

    def start(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        capture_filter: str | None = None,
        ssl_insecure: bool = False,
        upstream_proxy: str | None = None,
        extra_options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Start mitmproxy in a background thread."""
        with self._lock:
            if self.is_running:
                return {
                    "success": False,
                    "error": f"Proxy already running on {self.listen_host}:{self.listen_port}",
                }

            self._ready.clear()
            self._thread = threading.Thread(
                target=self._run_proxy,
                args=(host, port, capture_filter, ssl_insecure, upstream_proxy, extra_options),
                daemon=True,
            )
            self._thread.start()
            ready = self._ready.wait(timeout=10)
            if not ready:
                return {
                    "success": False,
                    "error": "Proxy failed to start within 10 seconds",
                }

            self._options = {
                "host": host,
                "port": port,
                "capture_filter": capture_filter,
                "ssl_insecure": ssl_insecure,
                "upstream_proxy": upstream_proxy,
                "extra_options": extra_options,
            }

        logger.info(f"mitmproxy started on {host}:{port}")
        result: dict[str, Any] = {
            "success": True,
            "host": host,
            "port": port,
            "capture_filter": capture_filter,
        }
        if extra_options:
            result["extra_options"] = extra_options
        return result

    def list_rules(self) -> list[Rule]:
        """Return the currently configured automatic rules."""
        return self.rules_addon.list_rules()

    def add_rule(self, rule: Rule) -> None:
        """Add or replace an automatic rule."""
        self.rules_addon.add_rule(rule)

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> Rule | None:
        """Update an existing automatic rule by id."""
        return self.rules_addon.update_rule(rule_id, updates)

    def delete_rule(self, rule_id: str) -> bool:
        """Delete an automatic rule by id."""
        return self.rules_addon.delete_rule(rule_id)

    def clear_rules(self) -> int:
        """Delete all automatic rules."""
        return self.rules_addon.clear_rules()

    def list_capture_rules(self) -> list[CaptureRule]:
        """Return the currently configured capture rules."""
        return self.capture_addon.list_rules()

    def add_capture_rule(self, rule: CaptureRule) -> None:
        """Add or replace a capture rule."""
        self.capture_addon.add_rule(rule)

    def update_capture_rule(
        self, rule_id: str, updates: dict[str, Any]
    ) -> CaptureRule | None:
        """Update an existing capture rule by id."""
        return self.capture_addon.update_rule(rule_id, updates)

    def delete_capture_rule(self, rule_id: str) -> bool:
        """Delete a capture rule by id."""
        return self.capture_addon.delete_rule(rule_id)

    def clear_capture_rules(self) -> int:
        """Delete all capture rules."""
        return self.capture_addon.clear_rules()

    def clear_all(self, stop_proxy: bool = False) -> dict[str, Any]:
        """Clear all flows, automatic rules and capture rules.

        If ``stop_proxy`` is True, also stop the running proxy.
        """
        cleared_flows = self.store.clear()
        cleared_rules = self.rules_addon.clear_rules()
        cleared_capture_rules = self.capture_addon.clear_rules()
        self.mapping_state.clear_local_rules()
        self.mapping_state.clear_remote_rules()
        result: dict[str, Any] = {
            "success": True,
            "cleared_flows": cleared_flows,
            "cleared_rules": cleared_rules,
            "cleared_capture_rules": cleared_capture_rules,
        }
        if stop_proxy:
            result["proxy_stopped"] = self.stop()["success"]
        return result

    # ------------------------------------------------------------------
    # URL mappings
    # ------------------------------------------------------------------

    def _sync_mapping_options(self, master: DumpMaster | None = None) -> None:
        """Update mitmproxy map_local/map_remote options from current state.

        If ``master`` is provided, update directly; otherwise use ``call()``
        so the update runs in the mitmproxy event loop.
        """
        local_specs = self.mapping_state.local_specs()
        remote_specs = self.mapping_state.remote_specs()

        if master is not None:
            master.options.update(map_local=local_specs, map_remote=remote_specs)
            return

        if self.is_running:
            self.call("set", "map_local", *local_specs)
            self.call("set", "map_remote", *remote_specs)

    def list_map_local_rules(self) -> list[MapLocalRule]:
        return self.mapping_state.list_local_rules()

    def add_map_local_rule(self, rule: MapLocalRule) -> None:
        self.mapping_state.add_local_rule(rule)
        self._sync_mapping_options()

    def delete_map_local_rule(self, rule_id: str) -> bool:
        deleted = self.mapping_state.delete_local_rule(rule_id)
        if deleted:
            self._sync_mapping_options()
        return deleted

    def clear_map_local_rules(self) -> int:
        count = self.mapping_state.clear_local_rules()
        self._sync_mapping_options()
        return count

    def list_map_remote_rules(self) -> list[MapRemoteRule]:
        return self.mapping_state.list_remote_rules()

    def add_map_remote_rule(self, rule: MapRemoteRule) -> None:
        self.mapping_state.add_remote_rule(rule)
        self._sync_mapping_options()

    def delete_map_remote_rule(self, rule_id: str) -> bool:
        deleted = self.mapping_state.delete_remote_rule(rule_id)
        if deleted:
            self._sync_mapping_options()
        return deleted

    def clear_map_remote_rules(self) -> int:
        count = self.mapping_state.clear_remote_rules()
        self._sync_mapping_options()
        return count

    def call(self, command_name: str, *args: Any, timeout: float = 30) -> Any:
        """Thread-safely call a mitmproxy command in its event loop."""
        with self._lock:
            master = self._master
            loop = self._loop

        if master is None or loop is None:
            raise RuntimeError("Proxy is not running")

        async def _acall() -> Any:
            return master.commands.call(command_name, *args)

        future = asyncio.run_coroutine_threadsafe(_acall(), loop)
        return future.result(timeout=timeout)

    def stop(self) -> dict[str, Any]:
        """Stop the mitmproxy thread."""
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Proxy is not running"}

            master = self._master
            thread = self._thread
            self._master = None
            self._thread = None
            self._loop = None
            self._options = {}
            self._ready.clear()

        try:
            if master is not None:
                master.shutdown()
        except Exception as e:
            logger.warning(f"Error during mitmproxy shutdown: {e}")

        if thread is not None:
            thread.join(timeout=5)

        logger.info("mitmproxy stopped")
        return {"success": True}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.is_running,
                "host": self.listen_host,
                "port": self.listen_port,
                "capture_filter": self.capture_filter,
                "captured_flows": self.store.count(),
            }
