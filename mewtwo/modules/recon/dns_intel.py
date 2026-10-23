"""DNS intelligence — CNAME resolution and dangling-CNAME (takeover) detection.

Resolving the CNAME chain for each subdomain and matching the target against known
third-party service domains surfaces *candidate* takeovers before the HTTP fingerprint
check even runs. Uses ``dnspython`` when available; degrades to the stdlib resolver
(which cannot see CNAMEs) with a clear warning otherwise.
"""

from __future__ import annotations

# Provider domain fragment → service name. If a subdomain's CNAME points at one of these
# and the resource is unclaimed, it may be takeover-able.
TAKEOVER_PROVIDERS: dict[str, str] = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "myshopify.com": "Shopify",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "domains.tumblr.com": "Tumblr",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "ghost.io": "Ghost",
    "read-the-docs.io": "Read the Docs",
    "readthedocs.io": "Read the Docs",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "zendesk.com": "Zendesk",
    "unbouncepages.com": "Unbounce",
    "webflow.io": "Webflow",
    "wpengine.com": "WP Engine",
    "azurewebsites.net": "Azure",
    "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure",
    "desk.com": "Desk",
    "helpscoutdocs.com": "Help Scout",
    "statuspage.io": "Statuspage",
}


def match_provider(cname_target: str) -> str | None:
    """Return the service name if the CNAME target belongs to a takeover-prone provider."""
    t = (cname_target or "").lower().rstrip(".")
    for fragment, service in TAKEOVER_PROVIDERS.items():
        if t.endswith(fragment) or f".{fragment}" in t:
            return service
    return None


def resolve_cname(hostname: str) -> str | None:
    """Resolve the CNAME for a hostname. Requires dnspython; returns None otherwise."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None
    try:
        answers = dns.resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        return None
    return None


def find_takeover_candidates(hostnames: list[str]) -> list[dict]:
    """For each hostname, resolve the CNAME and flag takeover-prone targets.

    Returns a list of {hostname, cname, service} dicts for candidates only.
    """
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        from ...utils.console import warn
        warn("dnspython not installed — CNAME takeover detection skipped. "
             "Install with: pip install dnspython")
        return []

    candidates: list[dict] = []
    for host in hostnames:
        cname = resolve_cname(host)
        if not cname:
            continue
        service = match_provider(cname)
        if service:
            candidates.append({"hostname": host, "cname": cname, "service": service})
    return candidates
