"""Parameter discovery — find hidden/unlinked query parameters via reflection.

Many endpoints accept parameters that never appear in links or forms (debug flags, legacy
filters, admin toggles). This miner injects a unique canary value under a wordlist of common
parameter names and flags any that reflect in the response — those are live, undocumented
inputs that feed straight into the surface-mapping heuristics (and often hide IDOR/SQLi).
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

# Compact high-signal wordlist. Extend via a file for deeper mining.
COMMON_PARAMS = [
    "id", "page", "q", "search", "query", "s", "keyword", "callback", "redirect",
    "url", "next", "return", "returnurl", "r", "dest", "file", "path", "lang",
    "debug", "test", "admin", "preview", "draft", "format", "view", "mode",
    "sort", "order", "filter", "limit", "offset", "user", "user_id", "account",
    "token", "key", "api_key", "access", "role", "type", "action", "cmd", "do",
    "ref", "source", "utm_source", "template", "theme", "include", "load", "data",
]

_CANARY = "mewtw0canary9137"


def _inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


async def discover_params(
    url: str,
    wordlist: list[str] | None = None,
    concurrency: int = 15,
) -> list[str]:
    """Return parameter names (from the wordlist) whose canary reflects in the response."""
    words = wordlist or COMMON_PARAMS
    found: list[str] = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        timeout=10, verify=False, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0"},
    ) as client:
        # Baseline: does the canary already appear without being sent? (avoid FPs)
        try:
            base = await client.get(url)
            baseline_has_canary = _CANARY in base.text
        except Exception:
            return []

        if baseline_has_canary:
            return []

        async def probe(param: str) -> None:
            async with sem:
                test_url = _inject(url, param, _CANARY)
                try:
                    resp = await client.get(test_url)
                except Exception:
                    return
                if _CANARY in resp.text:
                    found.append(param)

        await asyncio.gather(*[probe(p) for p in words])

    return sorted(set(found))
