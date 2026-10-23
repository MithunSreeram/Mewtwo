"""Race-condition check — fire a parallel burst and look for limit-bypass signals.

This is inherently an *active, noisy* check: it sends N simultaneous requests to the same
endpoint to see whether a single-use / limited action (coupon redemption, withdrawal,
vote, invite accept) is processed more than once due to a TOCTOU window. It is gated to
the aggressive safety tier via ``aggressive_only`` and skips anything that looks read-only.
"""

from __future__ import annotations

import asyncio

import httpx

from .base import BaseCheck, FindingDraft

# Keywords that suggest a limited / single-use state-changing action worth racing.
_RACEABLE = (
    "redeem", "coupon", "voucher", "promo", "gift", "withdraw", "transfer",
    "vote", "like", "claim", "invite", "apply", "checkout", "purchase",
    "cancel", "confirm", "balance", "credit", "points", "reward",
)

_BURST = 20  # simultaneous requests


class RaceConditionCheck(BaseCheck):
    name = "race_condition"
    description = "Fire a concurrent burst at limited-use actions to detect TOCTOU races"
    vuln_class = "Race Condition"
    references = [
        "https://portswigger.net/web-security/race-conditions",
        "https://cwe.mitre.org/data/definitions/362.html",
    ]
    applicable_categories = ["business_logic", "authorization"]
    # Only run when the user opts into aggressive mode — this hammers the endpoint.
    aggressive_only = True

    async def run(self, vector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        url = vector.url
        if not any(kw in url.lower() for kw in _RACEABLE):
            return []

        # Baseline single request to learn the "normal" response.
        try:
            baseline = await client.get(url, timeout=10)
        except Exception:
            return []
        baseline_status = baseline.status_code
        baseline_len = len(baseline.text)

        async def one() -> tuple[int, int]:
            try:
                r = await client.get(url, timeout=10)
                return r.status_code, len(r.text)
            except Exception:
                return (0, 0)

        results = await asyncio.gather(*[one() for _ in range(_BURST)])
        ok = [r for r in results if r[0] == baseline_status and r != (0, 0)]

        # Heuristic: if nearly all parallel requests succeed identically to the baseline
        # for an action that should be single-use, that is a race-condition signal worth
        # manual confirmation (the app did not serialise the requests).
        success_ratio = len(ok) / _BURST if _BURST else 0
        if success_ratio < 0.5:
            return []

        evidence = (
            f"Baseline: HTTP {baseline_status}, {baseline_len} bytes\n"
            f"Fired {_BURST} concurrent requests at a limited-use action.\n"
            f"{len(ok)}/{_BURST} returned the same success response ({success_ratio:.0%}).\n"
            f"Manually confirm the side-effect occurred more than once (e.g. balance applied twice)."
        )
        if ai:
            triage = ai.triage_finding(self.name, url, evidence)
            if not triage.get("is_finding"):
                return []

        return [FindingDraft(
            title=f"Possible race condition at {url}",
            vuln_class=self.vuln_class,
            severity="medium",
            url=url,
            description=(
                "A limited-use state-changing endpoint processed a concurrent burst without "
                "apparent serialisation. This is a candidate for a TOCTOU race (e.g. redeeming a "
                "single-use coupon multiple times). Confirm the duplicated side-effect manually — "
                "this check only detects the lack of serialisation, not the business impact."
            ),
            evidence=evidence,
            references=self.references,
        )]
