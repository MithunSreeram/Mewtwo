"""Web hardening tests — Host-header allowlist (anti DNS-rebinding) and loopback guard."""

from fastapi.testclient import TestClient

from mewtwo.web.app import create_app


def test_allowlisted_host_ok():
    c = TestClient(create_app())  # TestClient sends Host: testserver (allowlisted)
    assert c.get("/api/health").status_code == 200


def test_rebinding_host_rejected():
    # A DNS-rebinding page's request arrives with Host: evil.com → rejected by TrustedHost.
    c = TestClient(create_app())
    r = c.get("/api/health", headers={"host": "evil.com"})
    assert r.status_code == 400  # Starlette returns 400 "Invalid host header"


def test_localhost_host_ok():
    c = TestClient(create_app(allowed_hosts=["localhost", "127.0.0.1", "testserver"]))
    assert c.get("/api/health", headers={"host": "localhost:8000"}).status_code == 200
    assert c.get("/api/health", headers={"host": "127.0.0.1:8000"}).status_code == 200


def test_loopback_guard_blocks_non_loopback_client():
    # TestClient's peer is "testclient" (not loopback) → the guard must reject when enabled.
    c = TestClient(create_app(allowed_hosts=["testserver"], loopback_only=True))
    assert c.get("/api/health").status_code == 403


def test_loopback_guard_off_by_default():
    c = TestClient(create_app())  # loopback_only defaults False
    assert c.get("/api/health").status_code == 200
