"""Tests for favicon hashing, DNS takeover matching, param injection, validators."""

import pytest

from mewtwo.modules.recon.favicon import _murmur3_x86_32, favicon_hash, identify
from mewtwo.modules.recon.dns_intel import match_provider
from mewtwo.modules.recon.param_miner import _inject
from mewtwo.utils.validators import in_scope, slugify, is_valid_domain


def test_murmur3_known_answers():
    # Canonical MurmurHash3 x86_32 (signed) known-answer vectors.
    assert _murmur3_x86_32(b"") == 0
    assert _murmur3_x86_32(b"foo") == -156908512


def test_favicon_hash_stable():
    data = b"\x00\x01\x02 fake-icon"
    assert favicon_hash(data) == favicon_hash(data)  # deterministic


def test_favicon_identify():
    assert identify(81586312) == "Jenkins"
    assert identify(1) is None


@pytest.mark.parametrize("cname,service", [
    ("myapp.herokuapp.com", "Heroku"),
    ("foo.s3.amazonaws.com", "AWS S3"),
    ("shop.myshopify.com", "Shopify"),
    ("x.github.io", "GitHub Pages"),
    ("cdn.acme.com", None),
    ("", None),
])
def test_match_provider(cname, service):
    assert match_provider(cname) == service


def test_param_inject():
    assert _inject("https://x.com/a?b=1", "debug", "C") == "https://x.com/a?b=1&debug=C"
    assert "q=Z" in _inject("https://x.com/", "q", "Z")


def test_in_scope():
    assert in_scope("https://api.acme.com/x", ["*.acme.com"])
    assert in_scope("https://acme.com/x", ["acme.com"])
    assert not in_scope("https://evil.com/x", ["*.acme.com"])


def test_slugify():
    assert slugify("Acme Corp!") == "acme-corp"
    assert slugify("  Hello_World  ") == "hello-world"


def test_valid_domain():
    assert is_valid_domain("example.com")
    assert not is_valid_domain("not a domain")
