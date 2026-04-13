"""XSS (Cross-Site Scripting) check — reflected and DOM-based."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft

_PAYLOADS_FILE = Path(__file__).parent.parent / "payloads" / "xss.txt"

_DEFAULT_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
]


def _load_payloads() -> list[str]:
    if _PAYLOADS_FILE.exists():
        return [l.strip() for l in _PAYLOADS_FILE.read_text().splitlines() if l.strip()]
    return _DEFAULT_PAYLOADS


class XSSCheck(BaseCheck):
    name = "xss"
    description = "Test for reflected XSS in URL parameters and form inputs"
    vuln_class = "XSS"
    references = [
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
    ]
    applicable_categories = ["client_side", "injection"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters

        if not params:
            return []

        payloads = _load_payloads()[:10]  # Test first 10 payloads
        parsed = urlparse(url)

        for param in params[:5]:  # Cap at 5 params per vector
            for payload in payloads:
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    req = client.build_request("GET", test_url)
                    resp = await client.send(req)
                except Exception:
                    continue

                body = resp.text
                # Reflected XSS: payload appears unencoded in response
                if payload in body or re.search(
                    re.escape(payload).replace("\\<", "<").replace("\\>", ">"),
                    body, re.I
                ):
                    from ....utils.evidence import format_request, format_response
                    raw_req = format_request(req)
                    raw_resp = format_response(resp)
                    evidence = self._evidence_snippet(
                        f"GET {test_url}",
                        f"HTTP {resp.status_code}\n{body[:400]}",
                    )

                    if ai:
                        triage = ai.triage_finding(self.name, test_url, evidence)
                        if not triage.get("is_finding"):
                            continue
                        severity = triage.get("severity", "medium")
                    else:
                        severity = "medium"

                    findings.append(FindingDraft(
                        title=f"Reflected XSS in `{param}` at {parsed.netloc}{parsed.path}",
                        vuln_class=self.vuln_class,
                        severity=severity,
                        url=url,
                        parameter=param,
                        description=f"Parameter `{param}` reflects input unsanitized. Payload: `{payload}`",
                        evidence=evidence,
                        raw_request=raw_req,
                        raw_response=raw_resp,
                        references=self.references,
                    ))
                    break  # One finding per param

        return findings
