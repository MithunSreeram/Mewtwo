"""httpx client factory with sensible defaults."""

from __future__ import annotations

import httpx

from .. import config


def make_client(
    *,
    headers: dict | None = None,
    proxy: str | None = None,
    timeout: int | None = None,
    follow_redirects: bool = True,
) -> httpx.AsyncClient:
    base_headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        ),
    }
    if headers:
        base_headers.update(headers)

    proxy_url = proxy or config.proxy()
    return httpx.AsyncClient(
        headers=base_headers,
        timeout=httpx.Timeout(timeout or config.timeout()),
        follow_redirects=follow_redirects,
        proxy=proxy_url,
        verify=False,  # Bug bounty: many targets have cert issues
    )
