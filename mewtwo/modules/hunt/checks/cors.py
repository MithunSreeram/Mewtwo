"""CORS misconfiguration check."""

from __future__ import annotations

import httpx

from .base import BaseCheck, FindingDraft

_ORIGINS_TO_TEST = [
    "https://evil.com",
    "null",
    "https://example.com.evil.com",
]


class CORSCheck(BaseCheck):
    name = "cors"
    description = "Test for CORS misconfiguration — wildcard, null origin, origin reflection"
    vuln_class = "CORS Misconfiguration"
    references = [
        "https://portswigger.net/web-security/cors",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "https://cwe.mitre.org/data/definitions/942.html",
    ]
    applicable_categories = ["configuration", "authorization"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url

        for origin in _ORIGINS_TO_TEST:
            try:
                resp = await client.get(
                    url,
                    headers={"Origin": origin},
                )
            except Exception:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            is_vuln = False
            severity = "low"
            description = ""

            if acao == "*" and acac == "true":
                # Cannot combine wildcard with credentials in spec, but misconfigured servers may
                is_vuln = True
                severity = "high"
                description = "Wildcard ACAO with credentials=true — credentials may be leaked cross-origin."

            elif acao == origin and origin == "null" and acac == "true":
                is_vuln = True
                severity = "high"
                description = "null origin accepted with credentials=true — exploitable via sandboxed iframe."

            elif acao == "https://evil.com" and acac == "true":
                is_vuln = True
                severity = "high"
                description = (
                    "Origin reflection with credentials=true — arbitrary origin can read authenticated responses. "
                    "An attacker on evil.com can make credentialed cross-origin requests."
                )

            elif acao == "*":
                is_vuln = True
                severity = "low"
                description = "Wildcard ACAO — any origin can read unauthenticated responses."

            if is_vuln:
                evidence = (
                    f"Request Origin: {origin}\n"
                    f"Response ACAO: {acao}\n"
                    f"Response ACAC: {acac or '(not set)'}"
                )

                if ai:
                    triage = ai.triage_finding(self.name, url, evidence)
                    if not triage.get("is_finding"):
                        continue
                    severity = triage.get("severity", severity)

                from urllib.parse import urlparse
                parsed = urlparse(url)
                findings.append(FindingDraft(
                    title=f"CORS Misconfiguration at {parsed.netloc}",
                    vuln_class=self.vuln_class,
                    severity=severity,
                    url=url,
                    description=description,
                    evidence=evidence,
                    references=self.references,
                ))
                break  # One finding per vector is enough

        return findings
