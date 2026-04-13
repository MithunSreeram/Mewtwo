"""Wayback Machine URL harvesting via the CDX API."""

from __future__ import annotations

import uuid
from datetime import datetime
from urllib.parse import urlparse

import httpx

from ...models.recon import DiscoveredURL
from ...utils.console import console, info, warn


_CDX_API = "http://web.archive.org/cdx/search/cdx"

# Extensions to skip — binaries, fonts, images
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov",
    ".pdf", ".zip", ".tar", ".gz",
    ".css",  # keep .js — can contain endpoints
}


def _should_keep(url: str) -> bool:
    path = urlparse(url).path.lower()
    for ext in _SKIP_EXTENSIONS:
        if path.endswith(ext):
            return False
    return True


async def fetch_wayback_urls(
    target_id: str,
    domain: str,
    include_subdomains: bool = True,
    limit: int = 10_000,
) -> list[DiscoveredURL]:
    """Query Wayback Machine CDX API and return DiscoveredURL list."""
    url_pattern = f"*.{domain}" if include_subdomains else domain
    info(f"Querying Wayback Machine for {url_pattern} (limit={limit})...")

    params = {
        "url": url_pattern,
        "output": "json",
        "fl": "original,statuscode,timestamp",
        "collapse": "urlkey",          # deduplicate by URL key
        "limit": str(limit),
        "filter": "statuscode:200",    # only successful responses
    }

    discovered: list[DiscoveredURL] = []
    seen: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            resp = await client.get(_CDX_API, params=params)
            if resp.status_code != 200:
                warn(f"Wayback CDX returned {resp.status_code}")
                return []

            rows = resp.json()
            # First row is the header ["original", "statuscode", "timestamp"]
            if not rows or len(rows) < 2:
                info("No historical URLs found.")
                return []

            for row in rows[1:]:  # skip header
                original, statuscode, timestamp = row[0], row[1], row[2]

                if original in seen or not _should_keep(original):
                    continue
                seen.add(original)

                parsed = urlparse(original)
                params: list[str] = []
                if parsed.query:
                    for pair in parsed.query.split("&"):
                        k = pair.split("=", 1)[0]
                        if k:
                            params.append(k)

                # Parse timestamp YYYYMMDDHHmmss → datetime
                discovered_at = datetime.utcnow()
                try:
                    discovered_at = datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S")
                except Exception:
                    pass

                discovered.append(DiscoveredURL(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    url=original,
                    status_code=int(statuscode) if statuscode.isdigit() else None,
                    parameters=params,
                    discovered_at=discovered_at,
                    source="wayback",
                ))

    except Exception as e:
        warn(f"Wayback Machine query failed: {e}")

    console.print(f"  [dim]Wayback Machine: {len(discovered)} historical URLs[/dim]")
    return discovered
