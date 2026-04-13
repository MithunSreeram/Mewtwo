"""Open Redirect check."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft

_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "///evil.com",
    "\x00https://evil.com",
    "https://evil.com%2f@example.com",
    "javascript:alert(1)",
]

_REDIRECT_PARAMS = re.compile(
    r"redirect|return|next|url|goto|target|destination|redir|continue|back|forward",
    re.I,
)


class OpenRedirectCheck(BaseCheck):
    name = "open_redirect"
    description = "Test redirect parameters for open redirect"
    vuln_class = "Open Redirect"
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/601.html",
    ]
    applicable_categories = ["client_side"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters

        redirect_params = [p for p in params if _REDIRECT_PARAMS.search(p)]
        if not redirect_params:
            return []

        parsed = urlparse(url)

        for param in redirect_params:
            for payload in _REDIRECT_PAYLOADS:
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    # Don't follow redirects — capture the redirect target
                    async with httpx.AsyncClient(
                        timeout=10, follow_redirects=False, verify=False
                    ) as no_follow:
                        resp = await no_follow.get(test_url)
                except Exception:
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location or location.startswith("//") or "javascript:" in location:
                        evidence = self._evidence_snippet(
                            f"GET {test_url}",
                            f"HTTP {resp.status_code}\nLocation: {location}",
                        )

                        severity = "medium"
                        if ai:
                            triage = ai.triage_finding(self.name, test_url, evidence)
                            if not triage.get("is_finding"):
                                continue
                            severity = triage.get("severity", "medium")

                        findings.append(FindingDraft(
                            title=f"Open Redirect via `{param}` at {parsed.netloc}{parsed.path}",
                            vuln_class=self.vuln_class,
                            severity=severity,
                            url=url,
                            parameter=param,
                            description=f"Redirect parameter `{param}` accepts unvalidated URLs. Server redirected to: `{location}`",
                            evidence=evidence,
                            references=self.references,
                        ))
                        break

        return findings
