"""JWT weakness check — alg:none, weak HMAC secrets, and algorithm confusion signals.

This check inspects JWTs the application has already emitted (in Set-Cookie headers or
response bodies). It does NOT forge-and-replay against the live app by default — that is
an active auth-bypass attempt that belongs behind the aggressive safety tier. Instead it
statically analyses the token and reports exploitable weaknesses with a ready-to-test
forged token in the evidence, which the hunter can replay manually.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

import httpx

from .base import BaseCheck, FindingDraft

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Small list of notoriously common signing secrets seen in tutorials/boilerplate.
_WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "password", "changeme", "jwt_secret",
    "your-256-bit-secret", "s3cr3t", "key", "admin", "token", "mysecret",
    "default", "test", "qwerty", "123456", "supersecret",
]


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _parse(token: str) -> tuple[dict, dict, str] | None:
    try:
        header_b64, payload_b64, _sig = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        return header, payload, header_b64 + "." + payload_b64
    except Exception:
        return None


def _crack_hs256(token: str) -> str | None:
    """Try the weak-secret wordlist against an HS256 token's signature."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    for secret in _WEAK_SECRETS:
        candidate = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(candidate, actual_sig):
            return secret
    return None


def _extract_tokens(resp: httpx.Response) -> list[str]:
    tokens: set[str] = set()
    for value in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
        tokens.update(_JWT_RE.findall(value))
    # Fallback for header objects without get_list
    tokens.update(_JWT_RE.findall(resp.headers.get("set-cookie", "")))
    tokens.update(_JWT_RE.findall(resp.headers.get("authorization", "")))
    tokens.update(_JWT_RE.findall(resp.text[:20000]))
    return [t for t in tokens if t.count(".") == 2]


class JWTCheck(BaseCheck):
    name = "jwt"
    description = "Analyse emitted JWTs for alg:none, weak HMAC secrets, and confusion risks"
    vuln_class = "JWT Weakness"
    references = [
        "https://portswigger.net/web-security/jwt",
        "https://cwe.mitre.org/data/definitions/347.html",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
    ]
    applicable_categories = ["authentication", "authorization"]

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        try:
            resp = await client.get(vector.url, timeout=10)
        except Exception:
            return []

        for token in _extract_tokens(resp)[:5]:
            parsed = _parse(token)
            if not parsed:
                continue
            header, payload, signing_input = parsed
            alg = str(header.get("alg", "")).lower()

            # 1. alg:none — signature not verified
            if alg == "none":
                findings.append(FindingDraft(
                    title=f"JWT accepts alg:none at {vector.url}",
                    vuln_class=self.vuln_class,
                    severity="high",
                    url=vector.url,
                    description=(
                        "A JWT with `alg: none` was observed. If the server honours it, an attacker "
                        "can forge arbitrary unsigned tokens (e.g. elevate `role` to admin)."
                    ),
                    evidence=f"Header: {json.dumps(header)}\nClaims: {json.dumps(payload)}",
                    references=self.references,
                ))
                continue

            # 2. Weak HMAC secret (HS256/384/512)
            if alg.startswith("hs"):
                secret = _crack_hs256(token)
                if secret:
                    forged = self._forge_hs256(signing_input, payload, secret)
                    findings.append(FindingDraft(
                        title=f"JWT signed with weak secret '{secret}' at {vector.url}",
                        vuln_class=self.vuln_class,
                        severity="critical",
                        url=vector.url,
                        description=(
                            f"The HMAC-signed JWT was cracked with the trivial secret `{secret}`. "
                            f"An attacker can mint tokens with any claims. A forged token with the "
                            f"same claims is provided below for manual verification."
                        ),
                        evidence=(
                            f"Cracked secret: {secret}\n"
                            f"Original claims: {json.dumps(payload)}\n"
                            f"Forged token (replay manually): {forged}"
                        ),
                        references=self.references,
                    ))
            # 3. RS256 present — flag algorithm-confusion worth manual testing
            elif alg.startswith("rs") and ai:
                triage = ai.triage_finding(
                    self.name, vector.url,
                    f"RS256 JWT observed. Header: {json.dumps(header)}",
                )
                if triage.get("is_finding"):
                    findings.append(FindingDraft(
                        title=f"JWT uses RS256 — test for alg-confusion at {vector.url}",
                        vuln_class=self.vuln_class,
                        severity=triage.get("severity", "medium"),
                        url=vector.url,
                        description=(
                            "An RS256-signed JWT was observed. If the public key is retrievable and "
                            "the server does not pin the algorithm, it may be vulnerable to RS256→HS256 "
                            "algorithm-confusion. Manual testing required."
                        ),
                        evidence=f"Header: {json.dumps(header)}\nClaims: {json.dumps(payload)}",
                        references=self.references,
                    ))

        return findings

    @staticmethod
    def _forge_hs256(signing_input: str, payload: dict, secret: str) -> str:
        # Re-sign the original claims to prove the secret works end-to-end.
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{signing_input}.{sig_b64}"
