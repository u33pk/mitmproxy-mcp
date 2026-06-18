"""mitmproxy integration: CaptureAddon and ProxyManager."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import options
from mitmproxy.addonmanager import Loader
from mitmproxy.tools.dump import DumpMaster

from mitmproxy_mcp.store import FlowStore

logger = logging.getLogger(__name__)


class CaptureAddon:
    """An addon that captures HTTP flows into a FlowStore."""

    def __init__(self, store: FlowStore, capture_filter: str | None = None) -> None:
        self.store = store
        self.capture_filter = capture_filter
        self._filter: flowfilter.TFilter | None = None

    def load(self, loader: Loader) -> None:
        if self.capture_filter:
            try:
                self._filter = flowfilter.parse(self.capture_filter)
            except ValueError as e:
                logger.warning(f"Invalid capture filter '{self.capture_filter}': {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        if self._filter is not None and not self._filter(flow):
            return
        self.store.add(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        # Also capture failed flows so errors are visible.
        if self._filter is not None and not self._filter(flow):
            return
        self.store.add(flow)


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

    def _run_proxy(
        self,
        host: str,
        port: int,
        capture_filter: str | None,
        ssl_insecure: bool,
        upstream_proxy: str | None,
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
        opts = options.Options(**opts_kwargs)

        async def _setup() -> DumpMaster:
            # DumpMaster needs a running event loop during construction.
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(CaptureAddon(self.store, capture_filter))
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
                args=(host, port, capture_filter, ssl_insecure, upstream_proxy),
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
            }

        logger.info(f"mitmproxy started on {host}:{port}")
        return {
            "success": True,
            "host": host,
            "port": port,
            "capture_filter": capture_filter,
        }

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
