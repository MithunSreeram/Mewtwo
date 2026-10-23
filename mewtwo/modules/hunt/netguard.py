"""Network guard — an httpx transport enforcing scope + rate limiting for every request.

Sitting at the transport layer means EVERY request a check makes — ``client.get``,
``client.post``, ``build_request``/``send`` — passes through scope enforcement and the
rate limiter, without each check needing to know about either. This is the hard guarantee
that Mewtwo never touches an out-of-scope host during active hunting.
"""

from __future__ import annotations

import httpx

from ...utils.console import warn
from ...utils.throttle import AsyncRateLimiter
from ...utils.validators import in_scope


class OutOfScopeError(Exception):
    """Raised when a request targets a host outside the configured scope."""


class ScopeRateLimitTransport(httpx.AsyncBaseTransport):
    """Wraps a real transport; blocks out-of-scope hosts and throttles throughput."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        scope_patterns: list[str],
        limiter: AsyncRateLimiter | None = None,
        enforce_scope: bool = True,
    ):
        self._inner = inner
        self._scope = scope_patterns or []
        self._limiter = limiter
        self._enforce = enforce_scope and bool(scope_patterns)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if self._enforce and not in_scope(url, self._scope):
            warn(f"[scope] blocked out-of-scope request: {url}")
            raise OutOfScopeError(url)
        if self._limiter is not None:
            await self._limiter.acquire()
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
