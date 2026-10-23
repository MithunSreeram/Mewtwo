"""SSTI (Server-Side Template Injection) check — arithmetic-marker probing."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft

# Each payload evaluates to 1337 if the engine renders it. We pick a product that is
# extremely unlikely to appear verbatim in a normal response (7 * 191 = 1337).
_MARKER = "1337"
_PAYLOADS = [
    "${7*191}",      # Java EL / Spring / Thymeleaf-ish
    "{{7*191}}",     # Jinja2 / Twig / Nunjucks
    "#{7*191}",      # Ruby / JSP EL
    "<%= 7*191 %>",  # ERB
    "{7*191}",       # some lightweight engines
    "*{7*191}",      # Thymeleaf
    "@(7*191)",      # Razor
]

# If the raw expression is reflected unchanged, it is NOT evaluated (likely plain XSS turf).
def _evaluated(body: str, payload: str) -> bool:
    return _MARKER in body and payload not in body


class SSTICheck(BaseCheck):
    name = "ssti"
    description = "Probe parameters for server-side template injection via arithmetic markers"
    vuln_class = "SSTI"
    references = [
        "https://portswigger.net/web-security/server-side-template-injection",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
        "https://cwe.mitre.org/data/definitions/1336.html",
    ]
    applicable_categories = ["injection"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters
        if not params:
            return []

        parsed = urlparse(url)

        for param in params[:5]:
            for payload in _PAYLOADS:
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                try:
                    resp = await client.get(test_url, timeout=10)
                except Exception:
                    continue

                if _evaluated(resp.text, payload):
                    evidence = self._evidence_snippet(
                        f"GET {test_url}\nPayload: {payload} (expects {_MARKER})",
                        f"HTTP {resp.status_code}\nMarker {_MARKER} rendered in response.",
                    )
                    severity = "critical"
                    if ai:
                        triage = ai.triage_finding(self.name, test_url, evidence)
                        if not triage.get("is_finding"):
                            continue
                        severity = triage.get("severity", "critical")

                    findings.append(FindingDraft(
                        title=f"SSTI in `{param}` at {parsed.path or '/'}",
                        vuln_class=self.vuln_class,
                        severity=severity,
                        url=url,
                        parameter=param,
                        description=(
                            f"Parameter `{param}` evaluated the template expression `{payload}` "
                            f"server-side (rendered `{_MARKER}`). SSTI frequently escalates to RCE "
                            f"depending on the engine. Identify the engine and attempt sandbox escape."
                        ),
                        evidence=evidence,
                        references=self.references,
                    ))
                    break  # one confirmed payload per param is enough

            if any(f.parameter == param for f in findings):
                continue

        return findings
