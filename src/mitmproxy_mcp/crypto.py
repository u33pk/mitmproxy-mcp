"""User-defined encryption/decryption handlers for transparent traffic transformation."""

from __future__ import annotations

import importlib.util
import logging
import sys
import threading
from abc import ABC
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from mitmproxy import flowfilter
from mitmproxy import http
from pydantic import BaseModel, ConfigDict, Field

from mitmproxy_mcp.events import EventBuffer
from mitmproxy_mcp.store import FlowStore

logger = logging.getLogger(__name__)


# Metadata keys used to store decrypted/modified plaintext on flows.
DECRYPTED_REQUEST_KEY = "mitmproxy_mcp_decrypted_request"
DECRYPTED_RESPONSE_KEY = "mitmproxy_mcp_decrypted_response"
MODIFIED_REQUEST_KEY = "mitmproxy_mcp_modified_request"
MODIFIED_RESPONSE_KEY = "mitmproxy_mcp_modified_response"
APPLIED_HANDLERS_KEY = "mitmproxy_mcp_crypto_handlers"


class CryptoResult(BaseModel):
    """Result returned by CryptoHandler transformation methods.

    A method returning ``None`` means "do not transform this object".
    """

    model_config = ConfigDict(extra="forbid")

    body: bytes | None = None
    headers: dict[str, str] | None = None
    remove_headers: list[str] | None = None
    metadata: dict[str, Any] | None = None
    drop: bool = False
    error: str | None = None


class CryptoHandler(ABC):
    """Base class for user-written encryption/decryption scripts.

    Subclasses must declare a unique ``id``. They may optionally set ``name``,
    ``filter`` (a mitmproxy flowfilter expression) and ``priority``.

    The addon injects ``store`` (the :class:`FlowStore`) and provides
    ``context`` (a per-handler dict for cross-request state). This makes it
    possible to implement dynamic keys, session state, or deriving secrets from
    previous traffic.
    """

    id: str = ""
    name: str = ""
    filter: str | None = None
    priority: int = 0

    def __init__(self) -> None:
        self.store: FlowStore | None = None
        self.context: dict[str, Any] = {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def on_load(self, store: FlowStore) -> None:
        """Called once when the script is loaded into the running proxy."""
        self.store = store

    def on_unload(self) -> None:
        """Called once when the script is unloaded. Override to release resources."""
        pass

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def _compiled_filter(self) -> flowfilter.TFilter | None:
        if not self.filter:
            return None
        try:
            return flowfilter.parse(self.filter)
        except ValueError as e:
            self._logger.warning(f"Invalid filter for handler '{self.id}': {e}")
            return None

    def match(self, flow: http.HTTPFlow) -> bool:
        """Return True if this handler wants to process the flow."""
        flt = self._compiled_filter()
        if flt is None:
            return True
        try:
            return bool(flt(flow))
        except Exception as e:
            self._logger.warning(f"Filter evaluation failed for handler '{self.id}': {e}")
            return False

    # ------------------------------------------------------------------
    # HTTP transformations
    # ------------------------------------------------------------------

    def decrypt_request(self, flow: http.HTTPFlow) -> CryptoResult | None:
        """Decrypt an outgoing request before it is shown to the user."""
        return None

    def encrypt_request(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult | None:
        """Encrypt a modified plaintext request before it is sent to the server."""
        return None

    def decrypt_response(self, flow: http.HTTPFlow) -> CryptoResult | None:
        """Decrypt a response before it is shown to the user."""
        return None

    def encrypt_response(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult | None:
        """Encrypt a modified plaintext response before it is returned to the client."""
        return None

    # ------------------------------------------------------------------
    # WebSocket transformations
    # ------------------------------------------------------------------

    def decrypt_websocket_message(self, flow: http.HTTPFlow, msg: Any) -> CryptoResult | None:
        """Decrypt a WebSocket message before it is shown to the user."""
        return None

    def encrypt_websocket_message(self, flow: http.HTTPFlow, msg: Any, plaintext: bytes) -> CryptoResult | None:
        """Encrypt a modified WebSocket message before it is forwarded."""
        return None


@dataclass
class LoadedCryptoScript:
    """Runtime record of a loaded crypto handler script."""

    id: str
    name: str
    path: str
    handler: CryptoHandler
    loaded_at: float
    error_count: int = 0
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "loaded_at": self.loaded_at,
            "error_count": self.error_count,
            "last_error": self.last_error,
        }


class CryptoAddon:
    """mitmproxy addon that applies user-written CryptoHandler scripts."""

    def __init__(
        self,
        store: FlowStore | None = None,
        event_buffer: EventBuffer | None = None,
    ) -> None:
        self._store = store
        self._event_buffer = event_buffer
        self._lock = threading.RLock()
        self._scripts: list[LoadedCryptoScript] = []

    def set_store(self, store: FlowStore) -> None:
        """Inject the FlowStore after construction."""
        with self._lock:
            self._store = store
            for script in self._scripts:
                script.handler.on_load(store)

    # ------------------------------------------------------------------
    # Script management (called from the MCP tool thread)
    # ------------------------------------------------------------------

    def _ensure_store(self) -> FlowStore:
        if self._store is None:
            raise RuntimeError("CryptoAddon has not been bound to a FlowStore")
        return self._store

    def load_script(self, path: str) -> LoadedCryptoScript:
        """Load a CryptoHandler from a Python file."""
        store = self._ensure_store()
        handler = _load_handler_from_path(path)

        with self._lock:
            # Replace existing script with the same id.
            existing = next((s for s in self._scripts if s.id == handler.id), None)
            if existing is not None:
                existing.handler.on_unload()
                self._scripts.remove(existing)

            handler.on_load(store)
            script = LoadedCryptoScript(
                id=handler.id,
                name=handler.name or handler.id,
                path=path,
                handler=handler,
                loaded_at=__import__("time").time(),
            )
            self._scripts.append(script)
            self._scripts.sort(key=lambda s: s.handler.priority, reverse=True)
            return script

    def unload_script(self, script_id: str) -> bool:
        """Unload a script by id."""
        with self._lock:
            for idx, script in enumerate(self._scripts):
                if script.id == script_id:
                    script.handler.on_unload()
                    self._scripts.pop(idx)
                    return True
            return False

    def reload_script(self, script_id: str) -> LoadedCryptoScript:
        """Reload an already-loaded script by id."""
        with self._lock:
            script = next((s for s in self._scripts if s.id == script_id), None)
        if script is None:
            raise ValueError(f"Crypto script '{script_id}' is not loaded")
        return self.load_script(script.path)

    def list_scripts(self) -> list[LoadedCryptoScript]:
        """Return all loaded scripts."""
        with self._lock:
            return list(self._scripts)

    def get_status(self, script_id: str) -> LoadedCryptoScript | None:
        """Return a single loaded script record including error state."""
        with self._lock:
            return next((s for s in self._scripts if s.id == script_id), None)

    def clear_scripts(self) -> int:
        """Unload all scripts."""
        with self._lock:
            count = len(self._scripts)
            for script in self._scripts:
                script.handler.on_unload()
            self._scripts.clear()
            return count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_handlers(self):
        with self._lock:
            scripts = list(self._scripts)
        for script in scripts:
            yield script

    def _record_error(self, script: LoadedCryptoScript, message: str) -> None:
        script.error_count += 1
        script.last_error = message
        logger.warning(message)
        if self._event_buffer is not None:
            self._event_buffer.emit(
                "crypto:error",
                {
                    "script_id": script.id,
                    "script_name": script.name,
                    "message": message,
                },
            )

    @staticmethod
    def _apply_to_flow(
        flow: http.HTTPFlow,
        result: CryptoResult,
        is_request: bool,
    ) -> None:
        """Apply a CryptoResult to an HTTPFlow request or response."""
        if result.drop:
            target = flow.request if is_request else flow.response
            if target is not None:
                target.kill()  # type: ignore[attr-defined]
            return

        target = flow.request if is_request else flow.response
        if target is None:
            return

        if result.body is not None:
            target.content = result.body

        if result.headers:
            for name, value in result.headers.items():
                target.headers[name] = value

        if result.remove_headers:
            for name in result.remove_headers:
                if name in target.headers:
                    del target.headers[name]

        if result.metadata:
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata.update(result.metadata)

    @staticmethod
    def _apply_to_websocket_message(msg: Any, result: CryptoResult) -> None:
        """Apply a CryptoResult to a WebSocketMessage."""
        if result is None:
            return
        if result.drop:
            msg.drop()
            return
        if result.body is not None:
            msg.content = result.body
        if result.metadata:
            if msg.metadata is None:
                msg.metadata = {}
            msg.metadata.update(result.metadata)

    def _mark_applied(self, flow: http.HTTPFlow, handler_id: str) -> None:
        if flow.metadata is None:
            flow.metadata = {}
        applied = set(flow.metadata.get(APPLIED_HANDLERS_KEY, []))
        applied.add(handler_id)
        flow.metadata[APPLIED_HANDLERS_KEY] = list(applied)

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    def _match_handler(self, flow: http.HTTPFlow) -> LoadedCryptoScript | None:
        for script in self._iter_handlers():
            try:
                if script.handler.match(flow):
                    return script
            except Exception as e:
                self._record_error(script, f"Handler '{script.id}' match() failed: {e}")
        return None

    def request(self, flow: http.HTTPFlow) -> None:
        """Hook called before the request is sent to the server."""
        script = self._match_handler(flow)
        if script is None:
            return

        handler = script.handler

        # If the user has edited the decrypted plaintext, encrypt it back.
        if flow.metadata and MODIFIED_REQUEST_KEY in flow.metadata:
            plaintext: bytes = flow.metadata[MODIFIED_REQUEST_KEY]
            try:
                result = handler.encrypt_request(flow, plaintext)
            except Exception as e:
                self._record_error(script, f"Handler '{script.id}' encrypt_request() failed: {e}")
                return
            if isinstance(result, CryptoResult):
                if result.error:
                    self._record_error(script, f"Handler '{script.id}': {result.error}")
                    return
                self._apply_to_flow(flow, result, is_request=True)
                self._mark_applied(flow, handler.id)
            return

        # Otherwise decrypt for inspection.
        try:
            result = handler.decrypt_request(flow)
        except Exception as e:
            self._record_error(script, f"Handler '{script.id}' decrypt_request() failed: {e}")
            return
        if isinstance(result, CryptoResult):
            if result.error:
                self._record_error(script, f"Handler '{script.id}': {result.error}")
                return
            if flow.metadata is None:
                flow.metadata = {}
            if result.body is not None:
                flow.metadata[DECRYPTED_REQUEST_KEY] = result.body
            self._apply_to_flow(flow, result, is_request=True)
            self._mark_applied(flow, handler.id)

    def response(self, flow: http.HTTPFlow) -> None:
        """Hook called after the response is received."""
        script = self._match_handler(flow)
        if script is None:
            return

        handler = script.handler

        # If the user has edited the decrypted plaintext, encrypt it back.
        if flow.metadata and MODIFIED_RESPONSE_KEY in flow.metadata:
            plaintext: bytes = flow.metadata[MODIFIED_RESPONSE_KEY]
            try:
                result = handler.encrypt_response(flow, plaintext)
            except Exception as e:
                self._record_error(script, f"Handler '{script.id}' encrypt_response() failed: {e}")
                return
            if isinstance(result, CryptoResult):
                if result.error:
                    self._record_error(script, f"Handler '{script.id}': {result.error}")
                    return
                self._apply_to_flow(flow, result, is_request=False)
                self._mark_applied(flow, handler.id)
            return

        # Otherwise decrypt for inspection.
        try:
            result = handler.decrypt_response(flow)
        except Exception as e:
            self._record_error(script, f"Handler '{script.id}' decrypt_response() failed: {e}")
            return
        if isinstance(result, CryptoResult):
            if result.error:
                self._record_error(script, f"Handler '{script.id}': {result.error}")
                return
            if flow.metadata is None:
                flow.metadata = {}
            if result.body is not None:
                flow.metadata[DECRYPTED_RESPONSE_KEY] = result.body
            self._apply_to_flow(flow, result, is_request=False)
            self._mark_applied(flow, handler.id)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Hook called for each WebSocket message."""
        if flow.websocket is None or not flow.websocket.messages:
            return

        script = self._match_handler(flow)
        if script is None:
            return

        handler = script.handler
        msg = flow.websocket.messages[-1]

        # If the user has edited the decrypted plaintext, encrypt it back.
        if msg.metadata and MODIFIED_REQUEST_KEY in msg.metadata:
            plaintext: bytes = msg.metadata[MODIFIED_REQUEST_KEY]
            try:
                result = handler.encrypt_websocket_message(flow, msg, plaintext)
            except Exception as e:
                self._record_error(script, f"Handler '{script.id}' encrypt_websocket_message() failed: {e}")
                return
            if isinstance(result, CryptoResult):
                if result.error:
                    self._record_error(script, f"Handler '{script.id}': {result.error}")
                    return
                self._apply_to_websocket_message(msg, result)
                self._mark_applied(flow, handler.id)
            return

        # Otherwise decrypt for inspection.
        try:
            result = handler.decrypt_websocket_message(flow, msg)
        except Exception as e:
            self._record_error(script, f"Handler '{script.id}' decrypt_websocket_message() failed: {e}")
            return
        if isinstance(result, CryptoResult):
            if result.error:
                self._record_error(script, f"Handler '{script.id}': {result.error}")
                return
            if msg.metadata is None:
                msg.metadata = {}
            if result.body is not None:
                msg.metadata[DECRYPTED_REQUEST_KEY] = result.body
            self._apply_to_websocket_message(msg, result)
            self._mark_applied(flow, handler.id)


# ------------------------------------------------------------------------------
# Script loading helpers
# ------------------------------------------------------------------------------


def _load_handler_from_path(path: str) -> CryptoHandler:
    """Load a CryptoHandler subclass from a Python file."""
    file_path = Path(path).expanduser().resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"Crypto script not found: {path}")

    module_name = f"mitmproxy_mcp_crypto_user_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load crypto script: {path}")

    module = importlib.util.module_from_spec(spec)
    # Keep the module in sys.modules so relative imports/debugging work.
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    # If the module declares CRYPTO_HANDLER, use it directly.
    explicit = getattr(module, "CRYPTO_HANDLER", None)
    if explicit is not None:
        if isinstance(explicit, type) and issubclass(explicit, CryptoHandler):
            return explicit()
        raise TypeError("CRYPTO_HANDLER must be a CryptoHandler subclass")

    # Otherwise find the unique CryptoHandler subclass in the module.
    candidates = [
        obj
        for obj in vars(module).values()
        if isinstance(obj, type)
        and issubclass(obj, CryptoHandler)
        and obj is not CryptoHandler
    ]
    if not candidates:
        raise ValueError(f"No CryptoHandler subclass found in {path}")
    if len(candidates) > 1:
        raise ValueError(
            f"Multiple CryptoHandler subclasses found in {path}; "
            "set module-level CRYPTO_HANDLER to choose one"
        )
    return candidates[0]()
