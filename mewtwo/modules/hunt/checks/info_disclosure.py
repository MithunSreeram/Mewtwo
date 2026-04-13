"""Information disclosure check — stack traces, debug modes, sensitive paths."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseCheck, FindingDraft

_SENSITIVE_PATHS = [
    "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/config.php", "/config.yml", "/config.yaml", "/application.yml",
    "/.git/config", "/.git/HEAD",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/phpinfo.php", "/info.php",
    "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/debug", "/debug/vars", "/debug/pprof/",
    "/.well-known/security.txt",
    "/api/swagger.json", "/swagger.json", "/openapi.json",
    "/graphql", "/graphql/schema",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/WEB-INF/web.xml",
    "/web.config",
    "/package.json", "/package-lock.json",
    "/composer.json",
    "/Makefile", "/Dockerfile",
]

_STACK_TRACE_PATTERNS = re.compile(
    r"Traceback \(most recent call|NullPointerException|Exception in thread|"
    r"at java\.|at org\.|at com\.|at sun\.|"
    r"Fatal error:|Warning:.*on line \d|Parse error:|"
    r"Microsoft VBScript|ActiveX component|"
    r"500 Internal Server Error.*stack|"
    r"DEBUG\s*=\s*True|debug_mode.*=.*true",
    re.I,
)

_SENSITIVE_DATA_PATTERNS = re.compile(
    r"password|passwd|secret|api_key|apikey|private_key|access_token|"
    r"aws_access|aws_secret|database_url|db_password",
    re.I,
)


class InfoDisclosureCheck(BaseCheck):
    name = "info_disclosure"
    description = "Check for exposed configuration files, stack traces, and debug endpoints"
    vuln_class = "Information Disclosure"
    references = [
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    ]
    applicable_categories = [
        "info_disclosure", "configuration", "authentication", "authorization",
    ]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        base_url = vector.url
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check sensitive paths
        for path in _SENSITIVE_PATHS:
            target_url = urljoin(base, path)
            try:
                resp = await client.get(target_url)
            except Exception:
                continue

            if resp.status_code not in (200, 403):
                continue

            body = resp.text
            severity = None
            description = ""

            if resp.status_code == 200:
                if path in ("/.env", "/.env.local", "/.env.production", "/config.php"):
                    if _SENSITIVE_DATA_PATTERNS.search(body):
                        severity = "critical"
                        description = f"Sensitive configuration file exposed: `{path}` contains credentials/secrets."
                    else:
                        severity = "high"
                        description = f"Configuration file `{path}` is publicly accessible."

                elif path in ("/.git/config", "/.git/HEAD"):
                    severity = "high"
                    description = f"Git repository metadata exposed at `{path}` — source code may be recoverable."

                elif "/actuator" in path:
                    severity = "high"
                    description = f"Spring Boot Actuator endpoint exposed: `{path}`"

                elif path in ("/phpinfo.php", "/info.php"):
                    severity = "medium"
                    description = "PHP configuration exposed via phpinfo()."

                elif path in ("/api/swagger.json", "/swagger.json", "/openapi.json", "/openapi.yaml"):
                    severity = "low"
                    description = f"API specification exposed at `{path}` — all endpoints documented."

                elif _STACK_TRACE_PATTERNS.search(body):
                    severity = "medium"
                    description = f"Stack trace or debug information exposed at `{path}`."

                elif len(body) > 20 and not severity:
                    severity = "low"
                    description = f"File `{path}` returned HTTP 200."

            if severity:
                evidence = self._evidence_snippet(
                    f"GET {target_url}",
                    f"HTTP {resp.status_code}\n{body[:300]}",
                )
                findings.append(FindingDraft(
                    title=f"Info Disclosure: {path} at {parsed.netloc}",
                    vuln_class=self.vuln_class,
                    severity=severity,
                    url=target_url,
                    description=description,
                    evidence=evidence,
                    references=self.references,
                ))

        # Check for stack traces in existing responses
        try:
            resp = await client.get(base_url)
            if _STACK_TRACE_PATTERNS.search(resp.text):
                findings.append(FindingDraft(
                    title=f"Stack trace/debug info exposed at {parsed.netloc}{parsed.path}",
                    vuln_class=self.vuln_class,
                    severity="medium",
                    url=base_url,
                    description="Application error page reveals internal stack trace or debug information.",
                    evidence=self._evidence_snippet(
                        f"GET {base_url}",
                        f"HTTP {resp.status_code}\n{resp.text[:400]}",
                    ),
                    references=self.references,
                ))
        except Exception:
            pass

        return findings
