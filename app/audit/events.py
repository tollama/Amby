from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, event: dict[str, Any]) -> None:
        stale: list[asyncio.Queue[dict[str, Any]]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                stale.append(queue)
        for queue in stale:
            self._subscribers.discard(queue)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)
