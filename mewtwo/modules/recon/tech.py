"""Technology fingerprinting via HTTP headers and response analysis."""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlparse

import httpx

from ...models.recon import Technology
from ...utils.console import warn


# Signature-based fingerprinting rules
_SIGNATURES: list[dict] = [
    # Web servers
    {"name": "Apache", "category": "Web Server", "header": "Server", "pattern": r"Apache/?([\d.]+)?"},
    {"name": "Nginx", "category": "Web Server", "header": "Server", "pattern": r"nginx/?([\d.]+)?"},
    {"name": "IIS", "category": "Web Server", "header": "Server", "pattern": r"Microsoft-IIS/?([\d.]+)?"},
    {"name": "Cloudflare", "category": "CDN", "header": "Server", "pattern": r"cloudflare"},
    {"name": "AWS CloudFront", "category": "CDN", "header": "Via", "pattern": r"CloudFront"},
    # Languages / frameworks
    {"name": "PHP", "category": "Language", "header": "X-Powered-By", "pattern": r"PHP/?([\d.]+)?"},
    {"name": "ASP.NET", "category": "Framework", "header": "X-Powered-By", "pattern": r"ASP\.NET"},
    {"name": "Express", "category": "Framework", "header": "X-Powered-By", "pattern": r"Express"},
    # Security headers (absence == interesting)
    {"name": "No-CSP", "category": "Missing Header", "header": "Content-Security-Policy", "absent": True},
    {"name": "No-HSTS", "category": "Missing Header", "header": "Strict-Transport-Security", "absent": True},
    # Cookies
    {"name": "Laravel", "category": "Framework", "header": "Set-Cookie", "pattern": r"laravel_session"},
    {"name": "Django", "category": "Framework", "header": "Set-Cookie", "pattern": r"csrftoken|sessionid"},
    {"name": "Rails", "category": "Framework", "header": "Set-Cookie", "pattern": r"_session_id"},
    {"name": "WordPress", "category": "CMS", "header": "Set-Cookie", "pattern": r"wordpress_"},
]

# Body patterns
_BODY_SIGNATURES: list[dict] = [
    {"name": "WordPress", "category": "CMS", "pattern": r"wp-content/|wp-includes/", "version_pattern": r"WordPress ([\d.]+)"},
    {"name": "Drupal", "category": "CMS", "pattern": r"Drupal\.settings|/sites/default/"},
    {"name": "Joomla", "category": "CMS", "pattern": r"/media/jui/|Joomla!"},
    {"name": "React", "category": "JS Framework", "pattern": r"__REACT_DEVTOOLS|react-root|data-reactroot"},
    {"name": "Angular", "category": "JS Framework", "pattern": r"ng-version=|ng-app="},
    {"name": "Vue.js", "category": "JS Framework", "pattern": r"__vue__|v-app"},
    {"name": "jQuery", "category": "JS Library", "pattern": r"jquery[.-]([\d.]+)\."},
    {"name": "Bootstrap", "category": "CSS Framework", "pattern": r"bootstrap[.-]([\d.]+)"},
    {"name": "Swagger UI", "category": "API Docs", "pattern": r"swagger-ui|SwaggerUIBundle"},
    {"name": "GraphQL", "category": "API", "pattern": r"graphql|__schema"},
    {"name": "Spring Boot", "category": "Framework", "pattern": r"spring-boot-devtools|Whitelabel Error Page"},
]


async def fingerprint_url(target_id: str, url: str) -> list[Technology]:
    """Fingerprint a single URL, return Technology models."""
    techs: list[Technology] = []
    host = urlparse(url).netloc

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    except Exception as e:
        warn(f"Tech fingerprint failed for {url}: {e}")
        return []

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text

    # Header-based detection
    for sig in _SIGNATURES:
        header_val = headers.get(sig["header"].lower(), "")
        if sig.get("absent"):
            if not header_val:
                techs.append(Technology(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    host=host,
                    name=sig["name"],
                    category=sig["category"],
                    confidence=90,
                ))
        elif sig.get("pattern") and re.search(sig["pattern"], header_val, re.I):
            m = re.search(sig["pattern"], header_val, re.I)
            version = m.group(1) if m and m.lastindex else ""
            techs.append(Technology(
                id=str(uuid.uuid4()),
                target_id=target_id,
                host=host,
                name=sig["name"],
                version=version or "",
                category=sig["category"],
                confidence=95,
            ))

    # Body-based detection
    for sig in _BODY_SIGNATURES:
        if re.search(sig["pattern"], body, re.I):
            version = ""
            if sig.get("version_pattern"):
                vm = re.search(sig["version_pattern"], body, re.I)
                version = vm.group(1) if vm else ""
            techs.append(Technology(
                id=str(uuid.uuid4()),
                target_id=target_id,
                host=host,
                name=sig["name"],
                version=version,
                category=sig["category"],
                confidence=80,
            ))

    # Deduplicate by name
    seen: set[str] = set()
    unique: list[Technology] = []
    for t in techs:
        if t.name not in seen:
            seen.add(t.name)
            unique.append(t)

    return unique
