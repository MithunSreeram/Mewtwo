"""Subdomain takeover check — detect dangling CNAMEs pointing at unclaimed services."""

from __future__ import annotations

import httpx

from .base import BaseCheck, FindingDraft

# Service fingerprints: (service, response signature indicating an unclaimed/dangling host).
# These are the canonical "not found" / "no such app" bodies the providers serve when a
# CNAME points at a bucket/app that no longer exists and can be claimed by an attacker.
_FINGERPRINTS: list[tuple[str, str]] = [
    ("GitHub Pages", "There isn't a GitHub Pages site here."),
    ("Heroku", "No such app"),
    ("AWS S3", "NoSuchBucket"),
    ("AWS S3", "The specified bucket does not exist"),
    ("Shopify", "Sorry, this shop is currently unavailable"),
    ("Fastly", "Fastly error: unknown domain"),
    ("Pantheon", "The gods are wise, but do not know of the site which you seek"),
    ("Tumblr", "Whatever you were looking for doesn't currently exist at this address"),
    ("Surge.sh", "project not found"),
    ("Bitbucket", "Repository not found"),
    ("Ghost", "The thing you were looking for is no longer here"),
    ("Cargo Collective", "If you're moving your domain away from Cargo"),
    ("Readthedocs", "unknown to Read the Docs"),
    ("Netlify", "Not Found - Request ID"),
    ("Zendesk", "Help Center Closed"),
    ("Unbounce", "The requested URL was not found on this server"),
    ("Webflow", "The page you are looking for doesn't exist or has been moved"),
    ("Wordpress", "Do you want to register"),
    ("Azure", "404 Web Site not found"),
    ("Desk", "Please try again or try Desk.com free for 14 days"),
    ("Help Scout", "No settings were found for this company"),
]


class SubdomainTakeoverCheck(BaseCheck):
    name = "subdomain_takeover"
    description = "Detect dangling subdomains that resolve to unclaimed third-party services"
    vuln_class = "Subdomain Takeover"
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
        "https://github.com/EdOverflow/can-i-take-over-xyz",
        "https://cwe.mitre.org/data/definitions/350.html",
    ]
    # Surfaced from subdomain / configuration heuristics.
    applicable_categories = ["configuration", "info_disclosure"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        url = vector.url
        try:
            resp = await client.get(url, timeout=10)
        except Exception:
            return []

        body = resp.text
        for service, signature in _FINGERPRINTS:
            if signature.lower() in body.lower():
                evidence = self._evidence_snippet(
                    f"GET {url}",
                    f"HTTP {resp.status_code}\nMatched {service} fingerprint:\n{signature}",
                )
                severity = "high"
                if ai:
                    triage = ai.triage_finding(self.name, url, evidence)
                    if not triage.get("is_finding"):
                        continue
                    severity = triage.get("severity", "high")

                return [FindingDraft(
                    title=f"Potential subdomain takeover ({service}) at {vector.url}",
                    vuln_class=self.vuln_class,
                    severity=severity,
                    url=url,
                    description=(
                        f"The host resolves to **{service}** but the backing resource appears "
                        f"unclaimed (matched the provider's 'not found' fingerprint). An attacker "
                        f"may be able to register the resource and serve content from this domain. "
                        f"Confirm the CNAME target is dangling before reporting."
                    ),
                    evidence=evidence,
                    references=self.references,
                )]

        return []
