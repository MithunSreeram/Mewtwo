"""URL, domain, and scope validation helpers."""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse


_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain.strip().lower()))


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def slugify(name: str) -> str:
    """Convert a target name to a filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_-]+", "-", slug)
    return slug.strip("-")


def in_scope(url: str, scope_patterns: list[str]) -> bool:
    """Return True if the URL matches at least one in-scope pattern."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
    except Exception:
        return False
    for pattern in scope_patterns:
        if fnmatch.fnmatch(host, pattern):
            return True
        # Also match by path prefix
        full = host + parsed.path
        if fnmatch.fnmatch(full, pattern):
            return True
    return False


def extract_domain(url: str) -> str | None:
    try:
        return urlparse(url).netloc.split(":")[0] or None
    except Exception:
        return None
