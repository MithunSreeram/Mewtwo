"""NoSQL injection check — operator-injection and boolean-differential probing."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft

# Query-string operator injection (PHP/Express array-style). `[$ne]` etc. coerce the
# backend into Mongo operators. We compare a TRUE-ish injection against a FALSE-ish one.
_TRUE_OPS = [("[$ne]", "x"), ("[$gt]", ""), ("[$regex]", ".*")]
_FALSE_OPS = [("[$eq]", "mewtwo_nonexistent_value_zzz")]

# JSON-body operator injection for APIs that take JSON.
_JSON_TRUE = {"$ne": "mewtwo_nope"}
_JSON_FALSE = {"$eq": "mewtwo_nonexistent_value_zzz"}

# Error signatures that leak a NoSQL backend.
_ERROR_SIGNATURES = [
    "MongoError", "mongodb", "BSON", "E11000", "$where", "unterminated",
    "CastError", "Mongoose", "couchdb", "unexpected token",
]


def _body_signature(text: str) -> tuple[int, int]:
    """Cheap response signature: (status-insensitive length bucket, line count)."""
    return (len(text), text.count("\n"))


class NoSQLiCheck(BaseCheck):
    name = "nosqli"
    description = "Probe for NoSQL (MongoDB-style) operator injection"
    vuln_class = "NoSQL Injection"
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
        "https://portswigger.net/web-security/nosql-injection",
        "https://cwe.mitre.org/data/definitions/943.html",
    ]
    applicable_categories = ["injection", "authentication"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters
        if not params:
            return []

        parsed = urlparse(url)

        for param in params[:5]:
            # --- 1. Error-based: send a raw operator and look for a backend leak ---
            qs = parse_qs(parsed.query)
            qs[f"{param}[$ne]"] = ["1"]
            err_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                err_resp = await client.get(err_url, timeout=10)
            except Exception:
                err_resp = None

            if err_resp is not None and any(
                sig.lower() in err_resp.text.lower() for sig in _ERROR_SIGNATURES
            ):
                evidence = self._evidence_snippet(
                    f"GET {err_url}",
                    f"HTTP {err_resp.status_code}\nNoSQL backend error leaked:\n{err_resp.text[:400]}",
                )
                severity = "high"
                if ai:
                    triage = ai.triage_finding(self.name, err_url, evidence)
                    if not triage.get("is_finding"):
                        continue
                    severity = triage.get("severity", "high")
                findings.append(FindingDraft(
                    title=f"NoSQL injection (error-based) in `{param}`",
                    vuln_class=self.vuln_class,
                    severity=severity,
                    url=url,
                    parameter=param,
                    description=f"Operator injection in `{param}` leaked a NoSQL backend error.",
                    evidence=evidence,
                    references=self.references,
                ))
                continue

            # --- 2. Boolean-differential: TRUE op vs FALSE op response divergence ---
            true_op, true_val = _TRUE_OPS[0]
            false_op, false_val = _FALSE_OPS[0]

            qs_true = parse_qs(parsed.query)
            qs_true[f"{param}{true_op}"] = [true_val]
            true_url = urlunparse(parsed._replace(query=urlencode(qs_true, doseq=True)))

            qs_false = parse_qs(parsed.query)
            qs_false[f"{param}{false_op}"] = [false_val]
            false_url = urlunparse(parsed._replace(query=urlencode(qs_false, doseq=True)))

            try:
                t_resp = await client.get(true_url, timeout=10)
                f_resp = await client.get(false_url, timeout=10)
            except Exception:
                continue

            t_sig = _body_signature(t_resp.text)
            f_sig = _body_signature(f_resp.text)
            len_diff = abs(t_sig[0] - f_sig[0])

            if (t_resp.status_code != f_resp.status_code) or len_diff > 200:
                evidence = (
                    f"TRUE op {param}{true_op}={true_val}: HTTP {t_resp.status_code}, {t_sig[0]} bytes\n"
                    f"FALSE op {param}{false_op}={false_val}: HTTP {f_resp.status_code}, {f_sig[0]} bytes\n"
                    f"Difference: {len_diff} bytes"
                )
                if ai:
                    triage = ai.triage_finding(self.name, url, evidence)
                    if not triage.get("is_finding"):
                        continue
                findings.append(FindingDraft(
                    title=f"NoSQL injection (boolean) in `{param}`",
                    vuln_class=self.vuln_class,
                    severity="high",
                    url=url,
                    parameter=param,
                    description=(
                        f"Operator injection in `{param}` produced a measurable response difference "
                        f"between a true-ish (`$ne`) and false-ish (`$eq`) operator ({len_diff} bytes), "
                        f"indicating the input reaches a NoSQL query unsanitised."
                    ),
                    evidence=evidence,
                    references=self.references,
                ))

        return findings
