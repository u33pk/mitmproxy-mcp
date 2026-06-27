"""mitmproxy integration: CaptureAddon and ProxyManager."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import websockets
from cryptography.hazmat.primitives import serialization
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import options
from mitmproxy.addonmanager import Loader
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster
from mitmproxy_rs import wireguard
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from mitmproxy_mcp.crypto import CryptoAddon, CryptoHandler
from mitmproxy_mcp.events import EventBuffer
from mitmproxy_mcp.mappings import MapLocalRule, MapRemoteRule, MappingState
from mitmproxy_mcp.rules import Rule, RulesAddon
from mitmproxy_mcp.store import FlowStore
from mitmproxy_mcp.websocket_rules import WebSocketRule, WebSocketRulesAddon

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
        event_buffer: EventBuffer | None = None,
        source_proxy: str = "main",
    ) -> None:
        self.store = store
        self.capture_filter = capture_filter
        self._filter: flowfilter.TFilter | None = None
        self._lock = threading.RLock()
        self._capture_rules: list[CaptureRule] = []
        self._event_buffer = event_buffer
        self._source_proxy = source_proxy
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

    def _emit_flow_captured(self, store_id: int, flow: http.HTTPFlow) -> None:
        if self._event_buffer is None:
            return
        self._event_buffer.emit(
            "flow:captured",
            {
                "store_id": store_id,
                "method": flow.request.method,
                "scheme": flow.request.scheme,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "status": flow.response.status_code if flow.response else None,
                "is_websocket": flow.websocket is not None,
            },
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if self.should_capture(flow):
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata["mitmproxy_mcp_source_proxy"] = self._source_proxy
            store_id = self.store.add(flow)
            self._emit_flow_captured(store_id, flow)

    def error(self, flow: http.HTTPFlow) -> None:
        # Also capture failed flows so errors are visible.
        if self.should_capture(flow):
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata["mitmproxy_mcp_source_proxy"] = self._source_proxy
            store_id = self.store.add(flow)
            self._emit_flow_captured(store_id, flow)

    # ------------------------------------------------------------------
    # WebSocket hooks
    # ------------------------------------------------------------------

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        # The HTTP upgrade response is already captured by `response`, but
        # ensure the WebSocket flow is tracked in case filters behave
        # differently at upgrade time.
        if self.should_capture(flow):
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata["mitmproxy_mcp_source_proxy"] = self._source_proxy
            store_id = self.store.add(flow)
            self._emit_flow_captured(store_id, flow)
            if self._event_buffer is not None:
                self._event_buffer.emit(
                    "websocket:connected",
                    {
                        "store_id": store_id,
                        "host": flow.request.host,
                        "path": flow.request.path,
                    },
                )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # Messages are appended directly to flow.websocket.messages on the
        # same object stored in FlowStore, so no extra bookkeeping is needed.
        if flow.websocket and flow.metadata:
            flow.metadata["websocket_message_count"] = len(flow.websocket.messages)

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        # Connection close state is stored on flow.websocket automatically.
        pass


@dataclass
class CaConfig:
    """Certificate / CA configuration managed by ca_ctl."""

    verify_upstream: bool | None = None
    upstream_ca_file: str | None = None
    upstream_ca_confdir: str | None = None
    client_cert: str | None = None
    cert_passphrase: str | None = None

    def to_options(self) -> dict[str, Any]:
        """Return mitmproxy option kwargs for this config."""
        opts: dict[str, Any] = {}
        if self.verify_upstream is not None:
            opts["ssl_insecure"] = not self.verify_upstream
        if self.upstream_ca_file:
            opts["ssl_verify_upstream_trusted_ca"] = self.upstream_ca_file
        if self.upstream_ca_confdir:
            opts["ssl_verify_upstream_trusted_confdir"] = self.upstream_ca_confdir
        if self.client_cert:
            opts["client_certs"] = self.client_cert
        if self.cert_passphrase:
            opts["cert_passphrase"] = self.cert_passphrase
        return opts


class ProxyManager:
    """Manages a mitmproxy DumpMaster or WebMaster running in a background thread."""

    def __init__(self, store: FlowStore, source_proxy: str = "main") -> None:
        self.store = store
        self._master: DumpMaster | WebMaster | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._lock = threading.RLock()
        self._options: dict[str, Any] = {}
        self._wireguard_config: str | None = None
        self._ca_config = CaConfig()
        self.event_buffer = EventBuffer()
        self.capture_addon = CaptureAddon(self.store, event_buffer=self.event_buffer, source_proxy=source_proxy)
        self.rules_addon = RulesAddon(event_buffer=self.event_buffer)
        self.websocket_rules_addon = WebSocketRulesAddon(event_buffer=self.event_buffer)
        self.crypto_addon = CryptoAddon(self.store, event_buffer=self.event_buffer)
        self.mapping_state = MappingState()

    def _run_proxy(
        self,
        host: str,
        port: int,
        capture_filter: str | None,
        ssl_insecure: bool,
        upstream_proxy: str | None,
        extra_options: dict[str, Any] | None,
        webui: bool,
        web_port: int,
    ) -> None:
        """Thread target that creates and runs the mitmproxy event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        opts_kwargs: dict[str, Any] = {
            "listen_host": host,
            "listen_port": port,
        }
        # ca_ctl config takes precedence over the legacy ssl_insecure parameter.
        if self._ca_config.verify_upstream is not None:
            opts_kwargs["ssl_insecure"] = not self._ca_config.verify_upstream
        else:
            opts_kwargs["ssl_insecure"] = ssl_insecure
        opts_kwargs.update(self._ca_config.to_options())

        if upstream_proxy:
            opts_kwargs["mode"] = [f"upstream:{upstream_proxy}"]
        if extra_options:
            opts_kwargs.update(extra_options)
        opts = options.Options(**opts_kwargs)

        async def _setup() -> DumpMaster | WebMaster:
            # DumpMaster/WebMaster needs a running event loop during construction.
            if webui:
                master: DumpMaster | WebMaster = WebMaster(opts, with_termlog=False)
                # Web options are registered by WebAddon during master construction;
                # set them after the master is created so they are recognized.
                master.options.update(
                    web_host=host,
                    web_port=web_port,
                    web_open_browser=False,
                )
            else:
                master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.capture_addon.set_capture_filter(capture_filter)
            master.addons.add(self.capture_addon)
            master.addons.add(self.rules_addon)
            master.addons.add(self.websocket_rules_addon)
            master.addons.add(self.crypto_addon)
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

    @property
    def webui(self) -> bool:
        return bool(self._options.get("webui", False))

    @property
    def web_port(self) -> int | None:
        return self._options.get("web_port")

    @property
    def web_url(self) -> str | None:
        if not self.webui or self.web_port is None:
            return None
        # If the master is a WebMaster, use its computed URL (includes auth token).
        if isinstance(self._master, WebMaster):
            return self._master.web_url
        host = self.listen_host or "127.0.0.1"
        return f"http://{host}:{self.web_port}"

    def start(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        capture_filter: str | None = None,
        ssl_insecure: bool = False,
        upstream_proxy: str | None = None,
        extra_options: dict[str, Any] | None = None,
        webui: bool = False,
        web_port: int = 8081,
    ) -> dict[str, Any]:
        """Start mitmproxy in a background thread."""
        with self._lock:
            if self.is_running:
                return {
                    "success": False,
                    "error": f"Proxy already running on {self.listen_host}:{self.listen_port}",
                }

            extra_options = extra_options or {}
            prepared_options, wg_config = self._prepare_wireguard(host, port, extra_options)
            self._wireguard_config = wg_config

            self._ready.clear()
            self._thread = threading.Thread(
                target=self._run_proxy,
                args=(host, port, capture_filter, ssl_insecure, upstream_proxy, prepared_options, webui, web_port),
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
                "extra_options": prepared_options,
                "webui": webui,
                "web_port": web_port,
            }

        self.event_buffer.emit(
            "proxy:started",
            {
                "host": host,
                "port": port,
                "capture_filter": capture_filter,
                "webui": webui,
                "web_port": web_port if webui else None,
            },
        )
        logger.info(f"mitmproxy started on {host}:{port}")
        result: dict[str, Any] = {
            "success": True,
            "host": host,
            "port": port,
            "capture_filter": capture_filter,
            "webui": webui,
        }
        if webui:
            result["web_port"] = web_port
            result["web_url"] = self.web_url
        if prepared_options:
            result["extra_options"] = prepared_options
        if wg_config:
            result["wireguard_config"] = wg_config
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
        """Clear all flows, automatic rules, capture rules and crypto scripts.

        If ``stop_proxy`` is True, also stop the running proxy.
        """
        cleared_flows = self.store.clear()
        cleared_rules = self.rules_addon.clear_rules()
        cleared_capture_rules = self.capture_addon.clear_rules()
        cleared_crypto_scripts = self.crypto_addon.clear_scripts()
        self.mapping_state.clear_local_rules()
        self.mapping_state.clear_remote_rules()
        result: dict[str, Any] = {
            "success": True,
            "cleared_flows": cleared_flows,
            "cleared_rules": cleared_rules,
            "cleared_capture_rules": cleared_capture_rules,
            "cleared_crypto_scripts": cleared_crypto_scripts,
        }
        if stop_proxy:
            result["proxy_stopped"] = self.stop()["success"]
        return result

    # ------------------------------------------------------------------
    # URL mappings
    # ------------------------------------------------------------------

    def _sync_mapping_options(self, master: DumpMaster | WebMaster | None = None) -> None:
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

    def _prepare_wireguard(
        self,
        host: str,
        port: int,
        extra_options: dict[str, Any],
    ) -> tuple[dict[str, Any], str | None]:
        """If WireGuard mode is requested, generate keys/config and rewrite mode."""
        modes = extra_options.get("mode")
        if not modes or modes != ["wireguard"]:
            return extra_options, None

        conf_path = Path.home() / ".mitmproxy" / "wireguard_mcp.conf"
        conf_path.parent.mkdir(parents=True, exist_ok=True)

        server_key = wireguard.genkey()
        client_key = wireguard.genkey()
        conf_path.write_text(
            json.dumps(
                {"server_key": server_key, "client_key": client_key},
                indent=4,
            )
        )

        client_conf = self._build_wireguard_client_conf(host, port, server_key, client_key)
        prepared = dict(extra_options)
        prepared["mode"] = [f"wireguard:{conf_path}"]
        return prepared, client_conf

    @staticmethod
    def _build_wireguard_client_conf(
        host: str,
        port: int,
        server_key: str,
        client_key: str,
    ) -> str:
        """Build a WireGuard client config matching mitmproxy's native output."""
        server_pubkey = wireguard.pubkey(server_key)
        # For endpoints, localhost only makes sense for local testing. Otherwise
        # callers should start the proxy on an interface/IP reachable by clients.
        endpoint = f"{host}:{port}"
        return (
            "[Interface]\n"
            f"PrivateKey = {client_key}\n"
            "Address = 10.0.0.1/32\n"
            "DNS = 10.0.0.53\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {server_pubkey}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = {endpoint}"
        )

    def wireguard_config(self) -> dict[str, Any]:
        """Return the WireGuard client config if WireGuard mode was used."""
        with self._lock:
            if self._wireguard_config is None:
                return {
                    "success": False,
                    "error": "Proxy is not running in WireGuard mode",
                }
            return {
                "success": True,
                "wireguard_config": self._wireguard_config,
                "endpoint": f"{self.listen_host}:{self.listen_port}",
            }

    # ------------------------------------------------------------------
    # Certificate / CA management
    # ------------------------------------------------------------------

    def ca_status(self) -> dict[str, Any]:
        """Return the current CA/certificate configuration."""
        with self._lock:
            return {
                "success": True,
                "verify_upstream": self._ca_config.verify_upstream,
                "upstream_ca_file": self._ca_config.upstream_ca_file,
                "upstream_ca_confdir": self._ca_config.upstream_ca_confdir,
                "client_cert": self._ca_config.client_cert,
                "cert_passphrase_set": self._ca_config.cert_passphrase is not None,
                "proxy_running": self.is_running,
            }

    def _apply_ca_option(self, name: str, value: Any) -> None:
        """Apply a single mitmproxy option in the running proxy."""
        if self.is_running:
            if isinstance(value, bool):
                self.call("set", name, "true" if value else "false")
            else:
                self.call("set", name, str(value) if value is not None else "")

    def set_verify_upstream(self, enabled: bool) -> dict[str, Any]:
        """Enable or disable upstream server certificate verification."""
        with self._lock:
            self._ca_config.verify_upstream = enabled
            self._apply_ca_option("ssl_insecure", not enabled)
        return {"success": True, "verify_upstream": enabled}

    def set_upstream_ca(self, ca_path: str) -> dict[str, Any]:
        """Set a custom CA file or directory for upstream verification."""
        path = Path(ca_path).expanduser()
        if not path.exists():
            return {"success": False, "error": f"CA path does not exist: {ca_path}"}

        with self._lock:
            if path.is_dir():
                self._ca_config.upstream_ca_confdir = str(path)
                self._ca_config.upstream_ca_file = None
                self._apply_ca_option("ssl_verify_upstream_trusted_confdir", str(path))
                self._apply_ca_option("ssl_verify_upstream_trusted_ca", "")
            else:
                self._ca_config.upstream_ca_file = str(path)
                self._ca_config.upstream_ca_confdir = None
                self._apply_ca_option("ssl_verify_upstream_trusted_ca", str(path))
                self._apply_ca_option("ssl_verify_upstream_trusted_confdir", "")
        return {"success": True, "upstream_ca": str(path)}

    def clear_upstream_ca(self) -> dict[str, Any]:
        """Remove the custom upstream CA setting."""
        with self._lock:
            self._ca_config.upstream_ca_file = None
            self._ca_config.upstream_ca_confdir = None
            self._apply_ca_option("ssl_verify_upstream_trusted_ca", "")
            self._apply_ca_option("ssl_verify_upstream_trusted_confdir", "")
        return {"success": True}

    def _combine_client_cert(
        self,
        cert_path: str,
        key_path: str | None,
        passphrase: str | None,
    ) -> str:
        """Combine certificate and optional key into a single PEM file."""
        cert_file = Path(cert_path).expanduser()
        cert_pem = cert_file.read_bytes()

        key_pem = b""
        if key_path:
            key_file = Path(key_path).expanduser()
            key_data = key_file.read_bytes()
            key = serialization.load_pem_private_key(
                key_data,
                password=passphrase.encode() if passphrase else None,
            )
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

        out_dir = Path.home() / ".mitmproxy"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"client_cert_{cert_file.stem}.pem"
        out_file.write_bytes(cert_pem + b"\n" + key_pem)
        return str(out_file)

    def set_client_cert(
        self,
        cert_path: str,
        key_path: str | None = None,
        passphrase: str | None = None,
    ) -> dict[str, Any]:
        """Set a client certificate for mTLS."""
        cert_file = Path(cert_path).expanduser()
        if not cert_file.exists():
            return {"success": False, "error": f"Certificate file does not exist: {cert_path}"}
        if key_path and not Path(key_path).expanduser().exists():
            return {"success": False, "error": f"Key file does not exist: {key_path}"}

        with self._lock:
            combined = self._combine_client_cert(cert_path, key_path, passphrase)
            self._ca_config.client_cert = combined
            if passphrase:
                self._ca_config.cert_passphrase = passphrase
            self._apply_ca_option("client_certs", combined)
            if passphrase:
                self._apply_ca_option("cert_passphrase", passphrase)
        return {"success": True, "client_cert": combined}

    def clear_client_cert(self) -> dict[str, Any]:
        """Remove the client certificate setting."""
        with self._lock:
            self._ca_config.client_cert = None
            self._ca_config.cert_passphrase = None
            self._apply_ca_option("client_certs", "")
            self._apply_ca_option("cert_passphrase", "")
        return {"success": True}

    def export_ca(self, output_dir: str | None = None) -> dict[str, Any]:
        """Copy the mitmproxy CA certificate to the requested directory."""
        src = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
        if not src.exists():
            return {
                "success": False,
                "error": f"mitmproxy CA certificate not found at {src}. Start the proxy once to generate it.",
            }
        dest_dir = Path(output_dir).expanduser() if output_dir else Path.cwd()
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        shutil.copy2(src, dest)
        return {"success": True, "path": str(dest)}

    # ------------------------------------------------------------------
    # WebSocket management
    # ------------------------------------------------------------------

    def list_websocket_rules(self) -> list[WebSocketRule]:
        """Return the currently configured WebSocket message modification rules."""
        return self.websocket_rules_addon.list_rules()

    def add_websocket_rule(self, rule: WebSocketRule) -> None:
        """Add or replace a WebSocket message modification rule."""
        self.websocket_rules_addon.add_rule(rule)

    def delete_websocket_rule(self, rule_id: str) -> bool:
        """Delete a WebSocket rule by id."""
        return self.websocket_rules_addon.delete_rule(rule_id)

    def clear_websocket_rules(self) -> int:
        """Delete all WebSocket rules."""
        return self.websocket_rules_addon.clear_rules()

    # ------------------------------------------------------------------
    # Crypto script management
    # ------------------------------------------------------------------

    def load_crypto_script(self, path: str) -> dict[str, Any]:
        """Load a CryptoHandler script from a Python file."""
        script = self.crypto_addon.load_script(path)
        return {"success": True, "script": script.to_dict()}

    def unload_crypto_script(self, script_id: str) -> dict[str, Any]:
        """Unload a crypto script by id."""
        deleted = self.crypto_addon.unload_script(script_id)
        return {"success": deleted}

    def reload_crypto_script(self, script_id: str) -> dict[str, Any]:
        """Reload a loaded crypto script by id."""
        script = self.crypto_addon.reload_script(script_id)
        return {"success": True, "script": script.to_dict()}

    def list_crypto_scripts(self) -> list[dict[str, Any]]:
        """Return all loaded crypto scripts."""
        return [s.to_dict() for s in self.crypto_addon.list_scripts()]

    def get_crypto_script_status(self, script_id: str) -> dict[str, Any] | None:
        """Return status for a single loaded crypto script."""
        script = self.crypto_addon.get_status(script_id)
        if script is None:
            return None
        return script.to_dict()

    def inject_websocket(
        self,
        store_id: int,
        to_client: bool,
        message: str,
        binary: bool = False,
        target: ProxyManager | None = None,
    ) -> dict[str, Any]:
        """Inject a message into an existing WebSocket connection.

        If *target* is provided, the inject command runs in that proxy's event
        loop (useful when the flow was captured by a different proxy instance).
        """
        flow = self.store.get(store_id)
        if flow is None:
            return {"success": False, "error": f"Flow with id {store_id} not found"}
        if flow.websocket is None:
            return {"success": False, "error": "Flow is not a WebSocket connection"}

        msg_bytes = message.encode("utf-8") if not binary else base64.b64decode(message)
        proxy = target or self
        try:
            proxy.call("inject.websocket", flow, to_client, msg_bytes, not binary)
        except Exception as e:
            return {"success": False, "error": f"Failed to inject message: {e}"}
        return {"success": True, "injected": 1}

    def connect_websocket(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        subprotocols: list[str] | None = None,
        messages: list[str] | None = None,
        wait_for: int = 0,
        timeout: float = 10,
    ) -> dict[str, Any]:
        """Actively open a WebSocket connection through the proxy and capture it."""
        if not self.is_running:
            return {
                "success": False,
                "error": "Proxy is not running. Start it with proxy_ctl(cmd='start') first.",
            }

        proxy_url = f"http://{self.listen_host}:{self.listen_port}"
        messages = messages or []
        parsed = urlparse(url)
        target_host = parsed.hostname or ""
        target_port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        target_path = parsed.path or "/"

        async def _run() -> list[str]:
            received: list[str] = []
            async with websockets.connect(
                url,
                proxy=proxy_url,
                additional_headers=headers or {},
                subprotocols=subprotocols or None,
                open_timeout=timeout,
            ) as ws:
                for msg in messages:
                    await ws.send(msg)
                for _ in range(wait_for):
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                        received.append(msg if isinstance(msg, str) else base64.b64encode(msg).decode("ascii"))
                    except asyncio.TimeoutError:
                        break
            return received

        try:
            # Give the capture a moment to register the connection before
            # looking it up; the websocket handshake completes synchronously.
            received = asyncio.run(_run())
        except Exception as e:
            return {"success": False, "error": f"WebSocket connection failed: {e}"}

        # Find the captured flow by matching host/port/path (mitmproxy stores
        # the upgrade request with an http/https scheme, so URL equality fails).
        flow_id: int | None = None
        for sid in sorted(self.store.snapshot().keys(), reverse=True):
            flow = self.store.get(sid)
            if (
                flow
                and flow.websocket
                and flow.request
                and flow.request.host == target_host
                and flow.request.port == target_port
                and flow.request.path == target_path
            ):
                flow_id = sid
                break

        return {
            "success": True,
            "flow_id": flow_id,
            "received": received,
            "sent": messages,
        }

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
            self._wireguard_config = None
            self._ready.clear()

        try:
            if master is not None:
                master.shutdown()
        except Exception as e:
            logger.warning(f"Error during mitmproxy shutdown: {e}")

        if thread is not None:
            thread.join(timeout=5)

        self.event_buffer.emit("proxy:stopped", {})
        logger.info("mitmproxy stopped")
        return {"success": True}

    def status(self) -> dict[str, Any]:
        with self._lock:
            result: dict[str, Any] = {
                "running": self.is_running,
                "host": self.listen_host,
                "port": self.listen_port,
                "capture_filter": self.capture_filter,
                "captured_flows": self.store.count(),
                "webui": self.webui,
            }
            if self.webui:
                result["web_port"] = self.web_port
                result["web_url"] = self.web_url
            if self._wireguard_config is not None:
                result["wireguard_config"] = self._wireguard_config
                result["wireguard_endpoint"] = f"{self.listen_host}:{self.listen_port}"
            return result
