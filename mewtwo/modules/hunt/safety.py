"""Payload safety tiers.

Bug-bounty programs ban destructive testing. A single ``'; DROP TABLE users--`` that
actually lands can get a researcher removed from a program, so Mewtwo defaults to a tier
that strips destructive payloads and skips noisy/active checks. The hunter opts into more
aggression explicitly.

Tiers:
    SAFE        Only non-mutating, low-noise payloads. No boolean/burst probing.
    NORMAL      Default. Read-only-ish probing; destructive SQL/commands stripped;
                aggressive_only checks (bursts) skipped.
    AGGRESSIVE  Everything, including destructive payloads and race/burst checks.
                Use only with explicit program authorisation.
"""

from __future__ import annotations

import re
from enum import Enum


class SafetyTier(str, Enum):
    SAFE = "safe"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


# Payloads that can mutate or destroy server-side state, or run OS commands.
_DESTRUCTIVE = re.compile(
    r"""
    \bDROP\s+TABLE\b     | \bDELETE\s+FROM\b   | \bTRUNCATE\b        |
    \bUPDATE\s+\w+\s+SET\b | \bINSERT\s+INTO\b | \bSHUTDOWN\b        |
    \bALTER\s+TABLE\b    | \bEXEC(?:UTE)?\b    | xp_cmdshell         |
    \brm\s+-rf\b         | \bmkfs\b            | \b:\(\)\{           |   # fork bomb
    \bformat\s+c:       | \bshutdown\b        | \breboot\b
    """,
    re.I | re.X,
)


def is_destructive(payload: str) -> bool:
    """True if the payload could mutate/destroy state or run OS commands."""
    return bool(_DESTRUCTIVE.search(payload or ""))


def filter_payloads(payloads: list[str], tier: SafetyTier) -> list[str]:
    """Drop destructive payloads unless running in AGGRESSIVE tier."""
    if tier == SafetyTier.AGGRESSIVE:
        return list(payloads)
    return [p for p in payloads if not is_destructive(p)]


def allow_check(check_cls, tier: SafetyTier) -> bool:
    """Whether a check class may run under the given tier."""
    if getattr(check_cls, "aggressive_only", False):
        return tier == SafetyTier.AGGRESSIVE
    return True
