"""Lightweight, thread-safe event buffer for MCP resources."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any


class EventBuffer:
    """A fixed-size buffer of short-lived internal events.

    Events are kept in insertion order; ``latest()`` returns the most recent
    entries first. The buffer is safe to emit from both the mitmproxy event
    loop and the MCP tool thread.
    """

    def __init__(self, max_size: int = 30) -> None:
        self._max_size = max_size
        self._events: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._lock = threading.RLock()

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        """Record a lightweight event."""
        payload = payload or {}
        event = {
            "type": event_type,
            "timestamp": time.time(),
            **payload,
        }
        with self._lock:
            self._events.append(event)

    def latest(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most recent events, newest first."""
        with self._lock:
            events = list(self._events)
        return list(reversed(events))[:limit]

    def clear(self) -> int:
        """Remove all events. Returns the number removed."""
        with self._lock:
            count = len(self._events)
            self._events.clear()
        return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
