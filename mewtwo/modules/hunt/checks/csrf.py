"""CSRF check — detect state-changing forms lacking anti-CSRF tokens."""

from __future__ import annotations

import re

import httpx

from .base import BaseCheck, FindingDraft

# Hidden-input / header names that indicate CSRF protection is present.
_TOKEN_NAMES = re.compile(
    r"csrf|xsrf|authenticity_token|__requestverificationtoken|anti-?forgery|nonce|_token",
    re.I,
)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_METHOD_RE = re.compile(r'method\s*=\s*["\']?\s*(post|put|delete|patch)', re.I)
_INPUT_NAME_RE = re.compile(r'<input\b[^>]*\bname\s*=\s*["\']?([^"\'>\s]+)', re.I)
_SAMESITE_RE = re.compile(r"samesite\s*=\s*(strict|lax)", re.I)


class CSRFCheck(BaseCheck):
    name = "csrf"
    description = "Detect state-changing forms without anti-CSRF tokens or SameSite cookies"
    vuln_class = "CSRF"
    references = [
        "https://owasp.org/www-community/attacks/csrf",
        "https://portswigger.net/web-security/csrf",
        "https://cwe.mitre.org/data/definitions/352.html",
    ]
    applicable_categories = ["client_side", "authentication", "business_logic"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        try:
            resp = await client.get(vector.url, timeout=10)
        except Exception:
            return []

        # If cookies are SameSite=Strict/Lax, cross-site POSTs are already mitigated.
        set_cookie = resp.headers.get("set-cookie", "")
        samesite_protected = bool(_SAMESITE_RE.search(set_cookie))

        for form_body in _FORM_RE.findall(resp.text):
            # Reconstruct the opening tag to read its method attribute.
            form_open_match = re.search(
                r"<form\b[^>]*>", resp.text[: resp.text.find(form_body) + 10], re.I
            )
            form_open = form_open_match.group(0) if form_open_match else ""
            if not _METHOD_RE.search(form_open):
                continue  # GET forms are not state-changing — skip

            input_names = _INPUT_NAME_RE.findall(form_body)
            has_token = any(_TOKEN_NAMES.search(n) for n in input_names) or bool(
                _TOKEN_NAMES.search(form_body)
            )

            if has_token or samesite_protected:
                continue

            evidence = self._evidence_snippet(
                f"GET {vector.url}",
                f"State-changing form with no CSRF token. Inputs: {', '.join(input_names[:15])}\n"
                f"Set-Cookie SameSite protected: {samesite_protected}",
            )
            severity = "medium"
            if ai:
                triage = ai.triage_finding(self.name, vector.url, evidence)
                if not triage.get("is_finding"):
                    continue
                severity = triage.get("severity", "medium")

            findings.append(FindingDraft(
                title=f"Possible CSRF: unprotected state-changing form at {vector.url}",
                vuln_class=self.vuln_class,
                severity=severity,
                url=vector.url,
                description=(
                    "A POST/PUT/DELETE/PATCH form was found with no detectable anti-CSRF token, "
                    "and session cookies are not SameSite-restricted. If the action is sensitive "
                    "and relies only on the session cookie, it may be forgeable cross-site. "
                    "Confirm by replaying the request without the Origin/Referer and token."
                ),
                evidence=evidence,
                references=self.references,
            ))
            break  # one representative form per page

        return findings
