"""Async BFS web crawler — discovers URLs, forms, and parameters."""

from __future__ import annotations

import asyncio
import re
import uuid
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from ...models.recon import DiscoveredURL
from ...utils.console import console, warn
from ...utils.validators import in_scope


_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    ".css",  # CSS not useful for attack surface
}

_LINK_RE = re.compile(r'href=["\']([^"\'#][^"\']*)["\']', re.I)
_FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.I)
_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.I)
_INTERESTING_HEADERS = {
    "server", "x-powered-by", "x-frame-options", "content-security-policy",
    "access-control-allow-origin", "x-content-type-options", "strict-transport-security",
}


async def crawl(
    target_id: str,
    seed_url: str,
    depth: int = 3,
    scope_patterns: list[str] | None = None,
    max_urls: int = 500,
    concurrency: int = 15,
) -> list[DiscoveredURL]:
    """BFS crawler. Returns DiscoveredURL models."""
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed_url, 0)])
    results: list[DiscoveredURL] = []
    sem = asyncio.Semaphore(concurrency)

    async def fetch(url: str, current_depth: int) -> list[tuple[str, int]]:
        async with sem:
            try:
                async with httpx.AsyncClient(
                    timeout=10, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            except Exception:
                return []

            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            forms = _extract_forms(resp.text, url)
            interesting = {
                k: v for k, v in resp.headers.items()
                if k.lower() in _INTERESTING_HEADERS
            }

            results.append(DiscoveredURL(
                id=str(uuid.uuid4()),
                target_id=target_id,
                url=url,
                method="GET",
                status_code=resp.status_code,
                content_type=resp.headers.get("content-type", ""),
                parameters=params,
                forms=forms,
                interesting_headers=dict(interesting),
            ))

            if current_depth >= depth:
                return []

            # Extract links for next level
            next_urls: list[tuple[str, int]] = []
            for href in _LINK_RE.findall(resp.text):
                abs_url = _normalize(urljoin(url, href))
                if not abs_url or abs_url in visited:
                    continue
                if scope_patterns and not in_scope(abs_url, scope_patterns):
                    continue
                if _skip_url(abs_url):
                    continue
                next_urls.append((abs_url, current_depth + 1))
            return next_urls

    while queue and len(results) < max_urls:
        batch = []
        while queue and len(batch) < concurrency:
            url, depth_level = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            batch.append((url, depth_level))

        if not batch:
            break

        tasks = [fetch(url, d) for url, d in batch]
        for new_links in await asyncio.gather(*tasks):
            for link, d in new_links:
                if link not in visited:
                    queue.append((link, d))

    console.print(f"  [dim]Crawled {len(results)} URLs[/dim]")
    return results


def _extract_forms(html: str, base_url: str) -> list[dict]:
    forms = []
    for action_match in FORM_RE.finditer(html):
        raw_form = action_match.group(0)
        action = action_match.group(1)
        inputs = _INPUT_RE.findall(raw_form)
        forms.append({
            "action": urljoin(base_url, action),
            "inputs": inputs,
        })
    return forms


# Fix: use correct regex variable
FORM_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', re.I | re.S)


def _normalize(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        # Remove fragment
        return parsed._replace(fragment="").geturl()
    except Exception:
        return None


def _skip_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)
