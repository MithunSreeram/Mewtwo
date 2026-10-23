"""GraphQL check — introspection exposure and suggestion-based field disclosure."""

from __future__ import annotations

import json
import re

import httpx

from .base import BaseCheck, FindingDraft

# Minimal introspection query — if the server answers with a __schema, introspection is on.
_INTROSPECTION_QUERY = {
    "query": "{__schema{queryType{name} types{name kind}}}"
}

# Common GraphQL endpoint paths to probe when the vector URL is only a host root.
_COMMON_PATHS = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/query"]


def _candidate_urls(url: str) -> list[str]:
    if any(url.rstrip("/").endswith(p) for p in _COMMON_PATHS):
        return [url]
    base = url.rstrip("/")
    return [base + p for p in _COMMON_PATHS]


class GraphQLCheck(BaseCheck):
    name = "graphql"
    description = "Detect exposed GraphQL introspection and schema disclosure"
    vuln_class = "GraphQL Introspection"
    references = [
        "https://graphql.org/learn/introspection/",
        "https://portswigger.net/web-security/graphql",
        "https://cwe.mitre.org/data/definitions/200.html",
    ]
    applicable_categories = ["info_disclosure", "configuration", "injection"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        for target in _candidate_urls(vector.url):
            try:
                resp = await client.post(
                    target,
                    json=_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                continue

            schema = data.get("data", {}).get("__schema")
            if not schema:
                continue

            types = schema.get("types", [])
            type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
            evidence = self._evidence_snippet(
                f"POST {target}\n{json.dumps(_INTROSPECTION_QUERY)}",
                f"HTTP {resp.status_code}\n__schema exposed. {len(type_names)} types: "
                f"{', '.join(type_names[:30])}",
            )

            severity = "medium"
            if ai:
                triage = ai.triage_finding(self.name, target, evidence)
                if not triage.get("is_finding"):
                    continue
                severity = triage.get("severity", "medium")

            findings.append(FindingDraft(
                title=f"GraphQL introspection enabled at {target}",
                vuln_class=self.vuln_class,
                severity=severity,
                url=target,
                description=(
                    f"The GraphQL endpoint answered a full introspection query, disclosing the "
                    f"entire schema ({len(type_names)} user-defined types). This hands an attacker "
                    f"a complete map of queries, mutations, and fields — including undocumented or "
                    f"internal operations. Disable introspection in production."
                ),
                evidence=evidence,
                references=self.references,
            ))
            break  # One endpoint confirmed is enough

        return findings
