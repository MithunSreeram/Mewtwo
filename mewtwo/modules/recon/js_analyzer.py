"""JavaScript file analysis — extract secrets, API endpoints, and credentials."""

from __future__ import annotations

import re
import uuid
from urllib.parse import urljoin

import httpx

from ...models.recon import JSSecret
from ...utils.console import warn


# Secret patterns: (type, regex, confidence)
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("api_key", r'(?:api[_-]?key|apikey)["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,})', "high"),
    ("aws_key", r'AKIA[0-9A-Z]{16}', "high"),
    ("aws_secret", r'(?:aws[_-]?secret|SecretAccessKey)["\s]*[:=]["\s]*([A-Za-z0-9/+=]{40})', "high"),
    ("google_api", r'AIza[0-9A-Za-z_\-]{35}', "high"),
    ("stripe_key", r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', "high"),
    ("jwt", r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "high"),
    ("private_key", r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "high"),
    ("password", r'(?:password|passwd|pwd)["\s]*[:=]["\s]*["\']([^"\']{6,})["\']', "medium"),
    ("token", r'(?:token|bearer|secret)["\s]*[:=]["\s]*["\']([A-Za-z0-9_\-\.]{20,})["\']', "medium"),
    ("endpoint", r'(?:api|endpoint|url|baseUrl)["\s]*[:=]["\s]*["\']([/][^"\']+)["\']', "medium"),
    ("internal_url", r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s"\']+', "high"),
    ("slack_webhook", r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', "high"),
    ("github_token", r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}', "high"),
    ("mailchimp", r'[0-9a-f]{32}-us[0-9]+', "medium"),
]

_JS_URL_RE = re.compile(
    r'(?:import|require|fetch|axios|XMLHttpRequest)[^;]*["\']([/][^"\'?\s]+)["\']',
    re.I,
)

_LINK_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


async def analyze_js_file(
    target_id: str,
    js_url: str,
) -> list[JSSecret]:
    """Download and analyze a JS file for secrets and endpoints."""
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as client:
            resp = await client.get(js_url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return []
            content = resp.text
    except Exception as e:
        warn(f"Failed to fetch JS {js_url}: {e}")
        return []

    secrets: list[JSSecret] = []
    seen_values: set[str] = set()

    for secret_type, pattern, confidence in _SECRET_PATTERNS:
        for match in re.finditer(pattern, content, re.I):
            value = match.group(1) if match.lastindex else match.group(0)
            if len(value) < 5 or value in seen_values:
                continue
            seen_values.add(value)
            secrets.append(JSSecret(
                id=str(uuid.uuid4()),
                target_id=target_id,
                source_url=js_url,
                secret_type=secret_type,
                value=value[:200],  # Truncate long values
                confidence=confidence,
            ))

    # Also extract API endpoints from JS
    for path_match in _JS_URL_RE.finditer(content):
        path = path_match.group(1)
        if path and len(path) > 2 and path not in seen_values:
            seen_values.add(path)
            secrets.append(JSSecret(
                id=str(uuid.uuid4()),
                target_id=target_id,
                source_url=js_url,
                secret_type="endpoint",
                value=path,
                confidence="medium",
            ))

    return secrets


async def find_js_files(base_url: str, html: str) -> list[str]:
    """Extract JS file URLs from an HTML page."""
    js_urls = []
    for match in _LINK_RE.finditer(html):
        src = match.group(1)
        if src.startswith("http"):
            js_urls.append(src)
        else:
            js_urls.append(urljoin(base_url, src))
    return js_urls


async def analyze_page_js(target_id: str, page_url: str) -> list[JSSecret]:
    """Fetch a page, find all JS files, analyze each one."""
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.get(page_url, headers={"User-Agent": "Mozilla/5.0"})
            html = resp.text
    except Exception:
        return []

    js_files = await find_js_files(page_url, html)
    all_secrets: list[JSSecret] = []
    for js_url in js_files[:20]:  # Cap at 20 JS files per page
        secrets = await analyze_js_file(target_id, js_url)
        all_secrets.extend(secrets)
    return all_secrets
