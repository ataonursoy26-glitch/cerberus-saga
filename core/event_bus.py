"""
core/event_bus.py
Real-time inter-module event management (Blueprint Volume 1).

Uses Redis Pub/Sub if installed; otherwise falls back to in-process asyncio
publish/subscribe. Requires no external infrastructure for the demo.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Awaitable, Callable

log = logging.getLogger("cerberus.bus")

Handler = Callable[[dict], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subscribers[topic].append(handler)

    async def publish(self, topic: str, payload: dict) -> None:
        log.debug("event: %s -> %s", topic, payload.get("stage", ""))
        await asyncio.gather(
            *(h(payload) for h in self._subscribers.get(topic, [])),
            return_exceptions=True,
        )


bus = EventBus()
