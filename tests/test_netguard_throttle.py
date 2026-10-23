"""Scope enforcement (transport) and rate-limiter tests."""

import time

import httpx
import pytest

from mewtwo.modules.hunt.netguard import ScopeRateLimitTransport, OutOfScopeError
from mewtwo.utils.throttle import AsyncRateLimiter


class _DummyTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        return httpx.Response(200, text="ok")


@pytest.mark.asyncio
async def test_scope_blocks_out_of_scope_host():
    inner = _DummyTransport()
    transport = ScopeRateLimitTransport(inner, scope_patterns=["*.acme.com"])
    async with httpx.AsyncClient(transport=transport) as client:
        # In scope — allowed
        r = await client.get("https://api.acme.com/")
        assert r.status_code == 200
        # Out of scope — blocked before hitting the inner transport
        with pytest.raises(OutOfScopeError):
            await client.get("https://evil.example.com/")
    assert inner.calls == 1  # only the in-scope request reached the wire


@pytest.mark.asyncio
async def test_scope_noop_without_patterns():
    inner = _DummyTransport()
    transport = ScopeRateLimitTransport(inner, scope_patterns=[])
    async with httpx.AsyncClient(transport=transport) as client:
        r = await client.get("https://anything.example.com/")
        assert r.status_code == 200
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_rate_limiter_throttles():
    # 5 req/s, burst 1 → 3 requests should take ~0.4s (2 waits of 0.2s)
    limiter = AsyncRateLimiter(rate=5, burst=1)
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.3  # allow slack; proves throttling occurred


@pytest.mark.asyncio
async def test_rate_limiter_zero_is_unlimited():
    limiter = AsyncRateLimiter(rate=0)
    start = time.monotonic()
    for _ in range(100):
        await limiter.acquire()
    assert time.monotonic() - start < 0.1
