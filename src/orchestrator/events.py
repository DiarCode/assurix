"""Asyncio event bus for decoupled agent communication."""

import asyncio
from collections.abc import Callable
from typing import Any


class EventBus:
    """Simple async event bus using callbacks."""

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable[[dict[str, Any]], Any]]] = {}

    def subscribe(self, event_type: str, handler: Callable[[dict[str, Any]], Any]) -> None:
        """Register a handler for an event type."""
        self._listeners.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: Callable[[dict[str, Any]], Any]) -> None:
        """Remove a handler for an event type."""
        if event_type in self._listeners:
            self._listeners[event_type] = [
                h for h in self._listeners[event_type] if h is not handler
            ]

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        """Emit an event to all subscribed handlers."""
        handlers = self._listeners.get(event_type, [])
        for handler in handlers:
            if asyncio.iscoroutinefunction(handler):
                await handler(payload)
            else:
                handler(payload)
