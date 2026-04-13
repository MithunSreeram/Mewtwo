"""Deterministic heuristics for attack surface mapping."""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlparse

from ...models.surface import AttackVector, VectorCategory


def map_from_recon(
    target_id: str,
    urls: list[dict],
    technologies: list[dict],
    js_secrets: list[dict],
    subdomains: list[dict],
) -> list[AttackVector]:
    """Apply heuristic rules to recon data and return attack vectors."""
    vectors: list[AttackVector] = []

    vectors.extend(_check_urls(target_id, urls))
    vectors.extend(_check_technologies(target_id, technologies, urls))
    vectors.extend(_check_js_secrets(target_id, js_secrets))
    vectors.extend(_check_subdomains(target_id, subdomains))

    # Deduplicate by (category, url)
    seen: set[tuple] = set()
    unique: list[AttackVector] = []
    for v in vectors:
        key = (v.category, v.url)
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return unique


# ---------------------------------------------------------------------------
# URL-based heuristics
# ---------------------------------------------------------------------------

_LOGIN_PATTERNS = re.compile(
    r"login|signin|sign-in|auth|sso|oauth|saml|token|session", re.I
)
_ADMIN_PATTERNS = re.compile(
    r"admin|dashboard|manage|control|panel|backoffice|backend|staff|internal", re.I
)
_FILE_UPLOAD_PATTERNS = re.compile(
    r"upload|import|attach|file|document|media|avatar|photo|image", re.I
)
_REDIRECT_PARAMS = re.compile(
    r"redirect|return|next|url|goto|target|destination|redir|continue", re.I
)
_IDOR_PARAMS = re.compile(
    r"\bid\b|user_id|account_id|order_id|invoice_id|ticket_id|record_id|uid|uuid", re.I
)
_SSRF_PARAMS = re.compile(
    r"url|uri|path|src|source|dest|destination|target|proxy|fetch|load|import|callback", re.I
)
_SQLI_PARAMS = re.compile(
    r"search|query|q|keyword|filter|sort|order|id|page|limit|offset|where|having", re.I
)


def _check_urls(target_id: str, urls: list[dict]) -> list[AttackVector]:
    vectors: list[AttackVector] = []

    for url_row in urls:
        url = url_row.get("url", "")
        params = url_row.get("parameters", [])
        forms = url_row.get("forms", [])
        status = url_row.get("status_code", 200)

        if status in (401, 403):
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.AUTHORIZATION,
                title=f"Restricted endpoint: {urlparse(url).path}",
                description=f"URL returned {status} — may be bypassable.",
                url=url,
                risk_rating="medium",
                rationale=f"HTTP {status} responses sometimes indicate bypassable access controls.",
                source_recon_ids=[url_row.get("id", "")],
            ))

        if _LOGIN_PATTERNS.search(url):
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.AUTHENTICATION,
                title=f"Authentication endpoint: {urlparse(url).path}",
                description="Login/auth flow — test for brute force, account enumeration, weak tokens.",
                url=url,
                parameters=params,
                risk_rating="high",
                rationale="Auth endpoints are high-value targets for credential attacks.",
                source_recon_ids=[url_row.get("id", "")],
            ))

        if _ADMIN_PATTERNS.search(url):
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.AUTHORIZATION,
                title=f"Admin/privileged endpoint: {urlparse(url).path}",
                description="Admin interface — check for unauthorized access.",
                url=url,
                risk_rating="high",
                rationale="Admin panels accessible without proper auth can lead to full compromise.",
                source_recon_ids=[url_row.get("id", "")],
            ))

        if _FILE_UPLOAD_PATTERNS.search(url) or any(_FILE_UPLOAD_PATTERNS.search(str(f)) for f in forms):
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.INJECTION,
                title=f"File upload endpoint: {urlparse(url).path}",
                description="File upload — test for unrestricted file type, path traversal.",
                url=url,
                risk_rating="high",
                rationale="File upload endpoints are a common vector for RCE and stored XSS.",
                source_recon_ids=[url_row.get("id", "")],
            ))

        # Parameter-based heuristics
        for param in params:
            if _REDIRECT_PARAMS.search(param):
                vectors.append(AttackVector(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    category=VectorCategory.CLIENT_SIDE,
                    title=f"Open redirect parameter: {param}",
                    description=f"Parameter `{param}` in {url} may allow open redirect.",
                    url=url,
                    parameters=[param],
                    risk_rating="medium",
                    rationale="Redirect parameters are a classic open redirect vector.",
                    source_recon_ids=[url_row.get("id", "")],
                ))

            if _IDOR_PARAMS.search(param):
                vectors.append(AttackVector(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    category=VectorCategory.AUTHORIZATION,
                    title=f"Potential IDOR: {param} in {urlparse(url).path}",
                    description=f"Parameter `{param}` references an object ID — test for IDOR.",
                    url=url,
                    parameters=[param],
                    risk_rating="high",
                    rationale="Object ID parameters without proper authorization checks lead to IDOR.",
                    source_recon_ids=[url_row.get("id", "")],
                ))

            if _SSRF_PARAMS.search(param):
                vectors.append(AttackVector(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    category=VectorCategory.SSRF,
                    title=f"Potential SSRF: {param} in {urlparse(url).path}",
                    description=f"Parameter `{param}` takes a URL or path — test for SSRF.",
                    url=url,
                    parameters=[param],
                    risk_rating="high",
                    rationale="URL/path parameters that trigger server-side fetches lead to SSRF.",
                    source_recon_ids=[url_row.get("id", "")],
                ))

            if _SQLI_PARAMS.search(param):
                vectors.append(AttackVector(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    category=VectorCategory.INJECTION,
                    title=f"Potential SQLi: {param} in {urlparse(url).path}",
                    description=f"Parameter `{param}` may be passed to a SQL query.",
                    url=url,
                    parameters=[param],
                    risk_rating="medium",
                    rationale="Search/filter/sort parameters frequently reflect SQL queries.",
                    source_recon_ids=[url_row.get("id", "")],
                ))

        # CORS header check
        headers = url_row.get("interesting_headers", {})
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*" or acao == "null":
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.CONFIGURATION,
                title=f"CORS misconfiguration: {urlparse(url).netloc}",
                description=f"Access-Control-Allow-Origin: {acao}",
                url=url,
                risk_rating="medium",
                rationale="Wildcard or null CORS origin may allow cross-origin data theft.",
                source_recon_ids=[url_row.get("id", "")],
            ))

    return vectors


# ---------------------------------------------------------------------------
# Technology-based heuristics
# ---------------------------------------------------------------------------

def _check_technologies(
    target_id: str,
    technologies: list[dict],
    urls: list[dict],
) -> list[AttackVector]:
    vectors: list[AttackVector] = []
    tech_names = {t["name"].lower() for t in technologies}
    hosts = {t["host"] for t in technologies}

    for host in hosts:
        host_techs = {t["name"].lower() for t in technologies if t["host"] == host}

        if "wordpress" in host_techs:
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.CONFIGURATION,
                title=f"WordPress installation at {host}",
                description="Check for xmlrpc.php, REST API exposure, plugin vulnerabilities.",
                url=f"https://{host}",
                risk_rating="medium",
                rationale="WordPress is frequently misconfigured or running vulnerable plugins.",
            ))

        if "swagger ui" in host_techs or "graphql" in host_techs:
            api_type = "GraphQL" if "graphql" in host_techs else "Swagger/OpenAPI"
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.INFORMATION_DISCLOSURE,
                title=f"{api_type} documentation exposed at {host}",
                description=f"API documentation is publicly accessible — enumerate all endpoints.",
                url=f"https://{host}",
                risk_rating="medium",
                rationale="Exposed API docs reveal all endpoints, parameters, and auth schemes.",
            ))

        if "no-csp" in host_techs:
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.CLIENT_SIDE,
                title=f"No Content-Security-Policy at {host}",
                description="Missing CSP header increases XSS impact.",
                url=f"https://{host}",
                risk_rating="low",
                rationale="Absence of CSP allows XSS payloads to load arbitrary scripts.",
            ))

    return vectors


# ---------------------------------------------------------------------------
# JS Secrets heuristics
# ---------------------------------------------------------------------------

def _check_js_secrets(target_id: str, js_secrets: list[dict]) -> list[AttackVector]:
    vectors: list[AttackVector] = []
    for secret in js_secrets:
        if secret["secret_type"] in ("api_key", "aws_key", "stripe_key", "github_token", "jwt"):
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.INFORMATION_DISCLOSURE,
                title=f"Exposed {secret['secret_type']} in JS",
                description=f"Found in: {secret['source_url']} — value: {secret['value'][:30]}...",
                url=secret["source_url"],
                risk_rating="high",
                rationale=f"Hardcoded {secret['secret_type']} in client-side JS may grant unauthorized access.",
                source_recon_ids=[secret.get("id", "")],
            ))
        elif secret["secret_type"] == "endpoint":
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=VectorCategory.INFORMATION_DISCLOSURE,
                title=f"Hidden API endpoint in JS: {secret['value']}",
                description=f"Endpoint found in: {secret['source_url']}",
                url=secret["source_url"],
                risk_rating="low",
                rationale="Hidden/undocumented endpoints may lack proper access controls.",
                source_recon_ids=[secret.get("id", "")],
            ))
    return vectors


# ---------------------------------------------------------------------------
# Subdomain-based heuristics
# ---------------------------------------------------------------------------

_INTERESTING_SUBDOMAIN = re.compile(
    r"(?:dev|staging|stage|test|uat|qa|beta|internal|admin|api|vpn|mail|ftp|sftp|backup|jenkins|gitlab|jira|confluence|grafana|kibana|elastic|sonar)",
    re.I
)


def _check_subdomains(target_id: str, subdomains: list[dict]) -> list[AttackVector]:
    vectors: list[AttackVector] = []
    for sub in subdomains:
        if not sub.get("is_alive"):
            continue
        hostname = sub["hostname"]
        if _INTERESTING_SUBDOMAIN.search(hostname):
            category = VectorCategory.AUTHENTICATION
            if any(k in hostname for k in ("dev", "staging", "test", "uat", "beta")):
                category = VectorCategory.CONFIGURATION
            vectors.append(AttackVector(
                id=str(uuid.uuid4()),
                target_id=target_id,
                category=category,
                title=f"Interesting subdomain: {hostname}",
                description=f"Subdomain suggests privileged or non-production environment.",
                url=f"https://{hostname}",
                risk_rating="medium",
                rationale="Dev/staging/admin subdomains often have weaker security controls.",
                source_recon_ids=[sub.get("id", "")],
            ))
    return vectors
