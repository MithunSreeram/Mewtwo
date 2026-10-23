"""Async rate limiting — a simple token-bucket to keep scans polite."""

from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    """Token-bucket limiter. Allows up to ``rate`` requests per second (burstable)."""

    def __init__(self, rate: float, burst: int | None = None):
        # rate <= 0 disables limiting entirely.
        self.rate = max(rate, 0.0)
        self.capacity = burst if burst is not None else max(int(rate), 1)
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                # Not enough tokens — sleep until one is available.
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
