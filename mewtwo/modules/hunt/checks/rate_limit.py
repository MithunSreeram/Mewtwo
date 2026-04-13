"""Rate limit detection — identifies endpoints missing rate limiting."""

from __future__ import annotations

import asyncio
import time

import httpx

from .base import BaseCheck, FindingDraft
from ....utils.evidence import format_request, format_response

# Endpoints/paths that SHOULD have rate limiting
_SENSITIVE_PATH_PATTERNS = [
    "/login", "/signin", "/auth", "/oauth",
    "/register", "/signup",
    "/forgot", "/reset-password", "/password",
    "/otp", "/verify", "/2fa", "/mfa",
    "/api/auth", "/api/login", "/api/token",
]

# How many requests to fire in the burst test
_BURST_COUNT = 15
# Minimum requests that succeed before flagging (avoids false positives on 1-req endpoints)
_THRESHOLD = 10


def _path_is_sensitive(url: str) -> bool:
    url_lower = url.lower()
    return any(pat in url_lower for pat in _SENSITIVE_PATH_PATTERNS)


class RateLimitCheck(BaseCheck):
    name = "rate_limit"
    description = "Detect missing rate limiting on sensitive endpoints (login, auth, etc.)"
    vuln_class = "Missing Rate Limiting"
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
        "https://cwe.mitre.org/data/definitions/307.html",
    ]
    applicable_categories = ["authentication", "authorization", "configuration"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        url = vector.url

        if not _path_is_sensitive(url):
            return []

        findings: list[FindingDraft] = []

        # Build a lightweight probe request (HEAD or GET)
        method = "POST" if any(p in url.lower() for p in ("/login", "/signin", "/auth", "/token")) else "GET"

        success_count = 0
        last_req: httpx.Request | None = None
        last_resp: httpx.Response | None = None
        blocked_at: int | None = None

        # Fire burst of requests and track status codes
        for i in range(_BURST_COUNT):
            try:
                if method == "POST":
                    req = client.build_request(
                        "POST", url,
                        data={"username": "test", "password": "test"},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                else:
                    req = client.build_request("GET", url)

                resp = await client.send(req)
                last_req = req
                last_resp = resp

                # 429 / 503 indicates rate limiting is present — good
                if resp.status_code in (429, 503):
                    blocked_at = i + 1
                    break

                # Count non-error responses (200-499 excluding rate limit codes)
                if resp.status_code < 500:
                    success_count += 1

            except Exception:
                break

            # Small delay to avoid hammering
            await asyncio.sleep(0.1)

        # If we sent _THRESHOLD+ requests and were never blocked → likely no rate limit
        if blocked_at is None and success_count >= _THRESHOLD:
            raw_req = format_request(last_req) if last_req else ""
            raw_resp = format_response(last_resp) if last_resp else ""

            evidence_note = (
                f"Sent {success_count} {method} requests to {url} without triggering "
                f"rate limiting (HTTP 429). Endpoint may be vulnerable to brute-force or "
                f"credential stuffing attacks."
            )

            findings.append(FindingDraft(
                title=f"Missing Rate Limiting on {url}",
                vuln_class=self.vuln_class,
                severity="medium",
                url=url,
                description=(
                    f"{success_count} consecutive {method} requests to `{url}` returned "
                    f"non-error responses with no HTTP 429 or lockout observed. "
                    f"Sensitive authentication endpoints should enforce rate limiting."
                ),
                evidence=evidence_note,
                raw_request=raw_req,
                raw_response=raw_resp,
                references=self.references,
            ))
        elif blocked_at:
            # Rate limiting detected — no finding, but log it
            pass

        return findings
