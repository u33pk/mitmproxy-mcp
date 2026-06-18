"""Thread-safe in-memory store for mitmproxy HTTPFlow objects."""

from __future__ import annotations

import fnmatch
import re
import threading
from collections.abc import Sequence
from typing import Any

from mitmproxy import http
from mitmproxy import io


class FlowStore:
    """Stores HTTPFlow objects with filtering, pagination and CRUD."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._flows: dict[int, http.HTTPFlow] = {}
        self._counter = 0

    def _next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def add(self, flow: http.HTTPFlow) -> int:
        """Add a flow to the store, returning the assigned store id."""
        store_id = self._next_id()
        with self._lock:
            self._flows[store_id] = flow
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata["mitmproxy_mcp_id"] = store_id
        return store_id

    def clear(self) -> int:
        """Remove all flows. Returns the number of removed flows."""
        with self._lock:
            count = len(self._flows)
            self._flows.clear()
        return count

    def get(self, store_id: int) -> http.HTTPFlow | None:
        with self._lock:
            return self._flows.get(store_id)

    def delete(self, store_id: int) -> bool:
        with self._lock:
            if store_id in self._flows:
                del self._flows[store_id]
                return True
            return False

    def update(
        self,
        store_id: int,
        comment: str | None = None,
        marked: bool | None = None,
        tags: list[str] | None = None,
    ) -> http.HTTPFlow | None:
        """Update flow metadata."""
        with self._lock:
            flow = self._flows.get(store_id)
            if flow is None:
                return None
            if comment is not None:
                flow.comment = comment
            if marked is not None:
                flow.marked = marked
            if tags is not None:
                if flow.metadata is None:
                    flow.metadata = {}
                flow.metadata["tags"] = tags
            return flow

    def count(self) -> int:
        with self._lock:
            return len(self._flows)

    def list_ids(self) -> list[int]:
        with self._lock:
            return list(self._flows.keys())

    def list(
        self,
        offset: int = 0,
        limit: int = 50,
        host: str | None = None,
        method: str | None = None,
        status: int | None = None,
        search: str | None = None,
    ) -> list[tuple[int, http.HTTPFlow]]:
        """Return a paginated, filtered list of (store_id, flow) tuples."""
        with self._lock:
            flows = list(self._flows.items())

        if host:
            flows = [
                (sid, f)
                for sid, f in flows
                if fnmatch.fnmatch(f.request.host.lower(), host.lower())
            ]
        if method:
            method = method.upper()
            flows = [(sid, f) for sid, f in flows if f.request.method.upper() == method]
        if status is not None:
            flows = [
                (sid, f)
                for sid, f in flows
                if f.response and f.response.status_code == status
            ]
        if search:
            pattern = re.compile(search, re.IGNORECASE)
            filtered: list[tuple[int, http.HTTPFlow]] = []
            for sid, f in flows:
                haystack = " ".join(
                    [
                        f.request.url or "",
                        f.request.method or "",
                        str(f.response.status_code) if f.response else "",
                        f.comment or "",
                    ]
                )
                if pattern.search(haystack):
                    filtered.append((sid, f))
            flows = filtered

        return flows[offset : offset + limit]

    def load(self, path: str) -> int:
        """Load flows from a .mitm file. Returns number of flows loaded."""
        count = 0
        for flow in io.read_flows_from_paths([path]):
            if isinstance(flow, http.HTTPFlow):
                self.add(flow)
                count += 1
        return count

    def save(self, path: str) -> int:
        """Save all flows to a .mitm file. Returns number of flows saved."""
        with self._lock:
            flows: Sequence[http.HTTPFlow] = list(self._flows.values())
        with open(path, "wb") as f:
            writer = io.FlowWriter(f)
            for flow in flows:
                writer.add(flow)
        return len(flows)

    def snapshot(self) -> dict[int, Any]:
        """Return a shallow snapshot of current store ids for replay use."""
        with self._lock:
            return dict(self._flows)
