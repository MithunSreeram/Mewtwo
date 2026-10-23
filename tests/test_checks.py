"""Behavioural tests for new hunt checks and surface heuristics."""

import base64
import hashlib
import hmac
import json

import httpx
import pytest

from mewtwo.models.surface import AttackVector, VectorCategory
from mewtwo.modules.hunt.checks.jwt import JWTCheck, _crack_hs256
from mewtwo.modules.hunt.checks.subdomain_takeover import SubdomainTakeoverCheck
from mewtwo.modules.hunt.checks.graphql import GraphQLCheck
from mewtwo.modules.hunt.checks.ssti import SSTICheck
from mewtwo.modules.hunt.nuclei import _result_to_finding
from mewtwo.modules.surface.heuristics import map_from_recon


def _vector(url, params=None, category=VectorCategory.INJECTION):
    return AttackVector(
        target_id="t", category=category, title="t", description="",
        url=url, parameters=params or [],
    )


def _make_jwt(secret: str, claims: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    signing_input = f"{header}.{payload}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{sig_b64}"


def test_jwt_crack_weak_secret():
    token = _make_jwt("secret", {"user": "admin"})
    assert _crack_hs256(token) == "secret"
    strong = _make_jwt("a-very-long-random-unguessable-secret-value", {"user": "x"})
    assert _crack_hs256(strong) is None


@pytest.mark.asyncio
async def test_jwt_check_flags_weak_secret(httpx_mock):
    token = _make_jwt("changeme", {"role": "user"})
    httpx_mock.add_response(headers={"Set-Cookie": f"session={token}; Path=/"}, text="ok")
    async with httpx.AsyncClient() as client:
        findings = await JWTCheck().run(_vector("https://x.com/", category=VectorCategory.AUTHENTICATION), client)
    assert findings and findings[0].severity == "critical"
    assert "changeme" in findings[0].evidence


@pytest.mark.asyncio
async def test_subdomain_takeover_fingerprint(httpx_mock):
    httpx_mock.add_response(text="There isn't a GitHub Pages site here.")
    async with httpx.AsyncClient() as client:
        findings = await SubdomainTakeoverCheck().run(
            _vector("https://gone.acme.com/", category=VectorCategory.CONFIGURATION), client
        )
    assert findings and "GitHub Pages" in findings[0].title


@pytest.mark.asyncio
async def test_graphql_introspection(httpx_mock):
    schema = {"data": {"__schema": {"queryType": {"name": "Query"},
              "types": [{"name": "User", "kind": "OBJECT"}, {"name": "__Type", "kind": "OBJECT"}]}}}
    httpx_mock.add_response(json=schema)
    async with httpx.AsyncClient() as client:
        findings = await GraphQLCheck().run(
            _vector("https://x.com/graphql", category=VectorCategory.INFORMATION_DISCLOSURE), client
        )
    assert findings and "introspection" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_ssti_detects_evaluation(httpx_mock):
    # Engine evaluated 7*191 -> 1337 and the raw payload is NOT reflected.
    httpx_mock.add_response(text="Result: 1337 done")
    async with httpx.AsyncClient() as client:
        findings = await SSTICheck().run(_vector("https://x.com/?name=a", ["name"]), client)
    assert findings and findings[0].vuln_class == "SSTI"


@pytest.mark.asyncio
async def test_ssti_ignores_pure_reflection(httpx_mock):
    # Payload reflected verbatim (no eval) -> not SSTI. The check tries every payload,
    # so the mocked response must be reusable across all those requests.
    httpx_mock.add_response(text="Hello ${7*191}", is_reusable=True)
    async with httpx.AsyncClient() as client:
        findings = await SSTICheck().run(_vector("https://x.com/?name=a", ["name"]), client)
    assert findings == []


def test_nuclei_result_mapping():
    f = _result_to_finding("tid", {
        "template-id": "exposed-env", "matched-at": "https://x.com/.env",
        "info": {"name": "Exposed .env", "severity": "high", "description": "leak"},
    })
    assert f.severity.value == "high"
    assert f.url == "https://x.com/.env"
    assert "nuclei" in f.tags


def test_surface_heuristics_idor_and_ssrf():
    urls = [{
        "id": "u1", "url": "https://x.com/api?user_id=5&redirect=/home",
        "parameters": ["user_id", "redirect"], "forms": [], "status_code": 200,
        "interesting_headers": {},
    }]
    vectors = map_from_recon("t", urls, [], [], [])
    cats = {v.category for v in vectors}
    assert VectorCategory.AUTHORIZATION in cats  # IDOR from user_id
    assert VectorCategory.CLIENT_SIDE in cats    # open redirect from redirect param
