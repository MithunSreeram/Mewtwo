"""Favicon hashing — Shodan-compatible mmh3 hash for tech/infra fingerprinting.

A favicon hash lets you pivot: the same hash across unrelated-looking hosts reveals shared
infrastructure, and known hashes map to specific products (Jenkins, GitLab, Jira, etc.).
Shodan computes ``mmh3.hash(base64.encodebytes(favicon_bytes))``. We ship a pure-Python
MurmurHash3 x86_32 so this works with zero extra dependencies; if the ``mmh3`` package is
installed we use it (identical result).
"""

from __future__ import annotations

import base64
from urllib.parse import urljoin

import httpx

from ...utils.console import warn


def _murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86 32-bit, returning a signed 32-bit int (Shodan style)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = (length & 0xFFFFFFFC)  # round down to 4-byte block

    for i in range(0, rounded_end, 4):
        k1 = (
            data[i]
            | (data[i + 1] << 8)
            | (data[i + 2] << 16)
            | (data[i + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # tail
    k1 = 0
    tail_index = rounded_end
    remainder = length & 3
    if remainder == 3:
        k1 ^= data[tail_index + 2] << 16
    if remainder >= 2:
        k1 ^= data[tail_index + 1] << 8
    if remainder >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # finalization
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # convert to signed 32-bit (Shodan reports signed)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(favicon_bytes: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 over the base64-encoded bytes."""
    b64 = base64.encodebytes(favicon_bytes)  # includes trailing newlines, like Python's
    try:
        import mmh3  # type: ignore
        return mmh3.hash(b64)
    except ImportError:
        return _murmur3_x86_32(b64)


async def fetch_favicon_hash(base_url: str) -> tuple[int, str] | None:
    """Fetch /favicon.ico from a host and return (hash, favicon_url), or None."""
    favicon_url = urljoin(base_url.rstrip("/") + "/", "favicon.ico")
    try:
        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
            resp = await client.get(favicon_url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200 or not resp.content:
                return None
            return favicon_hash(resp.content), favicon_url
    except Exception as e:
        warn(f"favicon fetch failed for {base_url}: {e}")
        return None


# A tiny starter map of well-known favicon hashes → product (extend as you hunt).
KNOWN_HASHES: dict[int, str] = {
    81586312: "Jenkins",
    1278323681: "GitLab",
    -1255347582: "Jira",
    999357577: "Grafana",
    743365239: "Spring Boot (default)",
}


def identify(hash_value: int) -> str | None:
    return KNOWN_HASHES.get(hash_value)
