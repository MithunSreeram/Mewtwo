"""IDOR (Insecure Direct Object Reference) check."""

from __future__ import annotations

import re

import httpx

from .base import BaseCheck, FindingDraft


class IDORCheck(BaseCheck):
    name = "idor"
    description = "Test for IDOR by manipulating object ID parameters"
    vuln_class = "IDOR"
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        "https://cwe.mitre.org/data/definitions/639.html",
    ]
    applicable_categories = ["authorization"]

    _ID_PARAMS = re.compile(
        r"\b(id|user_id|uid|account_id|order_id|invoice_id|ticket_id|record_id|uuid|item_id)\b",
        re.I,
    )

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        url = vector.url
        params = vector.parameters

        id_params = [p for p in params if self._ID_PARAMS.search(p)]
        if not id_params:
            return []

        for param in id_params:
            # Try accessing neighbour IDs (id-1, id+1, 0, admin common IDs)
            for probe_val in ["1", "2", "0", "999999", "admin", "../1"]:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                original_val = qs.get(param, ["unknown"])[0]

                if original_val == probe_val:
                    continue

                qs[param] = [probe_val]
                new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                try:
                    resp = await client.get(new_url)
                except Exception:
                    continue

                # Compare: if 200 OK and response contains data, potential IDOR
                if resp.status_code == 200 and len(resp.text) > 100:
                    evidence = self._evidence_snippet(
                        f"GET {new_url}",
                        f"HTTP {resp.status_code}\n{resp.text[:300]}",
                    )

                    if ai:
                        triage = ai.triage_finding(
                            check_name=self.name,
                            vector_url=new_url,
                            evidence=evidence,
                        )
                        if not triage.get("is_finding"):
                            continue
                        severity = triage.get("severity", "high")
                    else:
                        severity = "high"

                    findings.append(FindingDraft(
                        title=f"Potential IDOR via {param} at {parsed.netloc}{parsed.path}",
                        vuln_class=self.vuln_class,
                        severity=severity,
                        url=new_url,
                        parameter=param,
                        description=f"Manipulating `{param}` from `{original_val}` to `{probe_val}` returned a 200 response with data.",
                        evidence=evidence,
                        references=self.references,
                    ))
                    break  # One finding per param is enough

        return findings
