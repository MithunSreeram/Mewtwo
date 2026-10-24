"""Background job hub for the web UI.

Runs recon / surface / hunt as asyncio tasks and fans progress events out to any connected
WebSocket clients. One job at a time (v1) — a second start is rejected while one runs.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable


class JobHub:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self.state: dict[str, Any] = {
            "status": "idle",     # idle | running | error
            "job": None,
            "detail": "",
            "summary": None,
        }

    # -- pub/sub for WebSocket clients --------------------------------------

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._subscribers.add(q)
        # Prime the new client with current state so late joiners aren't blank.
        q.put_nowait({"type": "state", **self.state})
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def emit(self, event: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    # -- job lifecycle ------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.state["status"] == "running"

    def start(self, name: str, factory: Callable[[Callable[[dict], None]], Awaitable[Any]]) -> None:
        """Start a job. ``factory`` receives a progress callback and returns a coroutine."""
        if self.running:
            raise RuntimeError("A job is already running")
        self.state = {"status": "running", "job": name, "detail": "", "summary": None}
        self.emit({"type": "job_start", "job": name})

        def progress(ev: dict) -> None:
            self.emit({"type": "progress", "job": name, **ev})

        async def runner() -> None:
            try:
                result = await factory(progress)
                self.state = {"status": "idle", "job": name, "detail": "done", "summary": result}
                self.emit({"type": "job_done", "job": name, "summary": result})
            except Exception as e:  # noqa: BLE001 — surface any failure to the UI
                self.state = {"status": "error", "job": name, "detail": str(e), "summary": None}
                self.emit({"type": "job_error", "job": name, "error": str(e)})

        self._task = asyncio.create_task(runner())
