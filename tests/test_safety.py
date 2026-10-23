"""Payload safety-tier tests — the guardrail that keeps destructive payloads off targets."""

from mewtwo.modules.hunt.safety import (
    SafetyTier, is_destructive, filter_payloads, allow_check,
)
from mewtwo.modules.hunt.checks.race_condition import RaceConditionCheck
from mewtwo.modules.hunt.checks.xss import XSSCheck


def test_destructive_detection():
    assert is_destructive("'; DROP TABLE users--")
    assert is_destructive("1; DELETE FROM accounts")
    assert is_destructive("; rm -rf /")
    assert is_destructive("'; TRUNCATE logs--")
    assert not is_destructive("' OR '1'='1")
    assert not is_destructive("<script>alert(1)</script>")
    assert not is_destructive("")


def test_filter_strips_destructive_below_aggressive():
    payloads = ["'", "' OR 1=1--", "'; DROP TABLE users--"]
    for tier in (SafetyTier.SAFE, SafetyTier.NORMAL):
        filtered = filter_payloads(payloads, tier)
        assert "'; DROP TABLE users--" not in filtered
        assert "' OR 1=1--" in filtered


def test_aggressive_keeps_everything():
    payloads = ["'", "'; DROP TABLE users--"]
    assert filter_payloads(payloads, SafetyTier.AGGRESSIVE) == payloads


def test_allow_check_gates_aggressive_only():
    # race_condition is aggressive_only → only runs in AGGRESSIVE
    assert not allow_check(RaceConditionCheck, SafetyTier.NORMAL)
    assert not allow_check(RaceConditionCheck, SafetyTier.SAFE)
    assert allow_check(RaceConditionCheck, SafetyTier.AGGRESSIVE)
    # a normal check runs in every tier
    assert allow_check(XSSCheck, SafetyTier.NORMAL)
    assert allow_check(XSSCheck, SafetyTier.AGGRESSIVE)
