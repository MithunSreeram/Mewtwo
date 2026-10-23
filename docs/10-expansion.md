# Mewtwo — Expansion Modules

This document covers the capabilities added on top of the original 9-phase pipeline:
seven new hunt checks, safety tiers, request-time scope enforcement, politeness throttling,
authenticated scanning, four recon additions, nuclei integration, three AI capabilities,
resumable recon, and the test suite.

---

## 1. New hunt checks

All live in `mewtwo/modules/hunt/checks/` and follow the existing `BaseCheck` contract, so
the runner dispatches them by `applicable_categories` exactly like the originals.

| Check | `name` | What it does |
|-------|--------|--------------|
| Subdomain takeover | `subdomain_takeover` | Matches ~20 provider "unclaimed resource" fingerprints (GitHub Pages, Heroku, S3, Shopify, …) against the response body. |
| GraphQL | `graphql` | Sends a minimal introspection query to common GraphQL paths; flags full `__schema` disclosure. |
| JWT | `jwt` | Parses JWTs from `Set-Cookie`/body; flags `alg:none`, cracks weak HMAC secrets with a wordlist, and forges a same-claims token into the evidence; flags RS256 for alg-confusion review. |
| SSTI | `ssti` | Injects arithmetic markers (`${7*191}`, `{{7*191}}`, …) and confirms server-side evaluation (`1337` rendered **and** the raw payload not reflected — avoids confusing it with plain reflection/XSS). |
| NoSQLi | `nosqli` | MongoDB-style operator injection (`[$ne]`, `[$gt]`), both error-based (backend leak) and boolean-differential. |
| CSRF | `csrf` | Finds state-changing forms (POST/PUT/DELETE/PATCH) with no anti-CSRF token and no SameSite cookie protection. |
| Race condition | `race_condition` | Fires a concurrent burst at limited-use actions (coupon/withdraw/vote) to detect missing serialisation. **Aggressive-tier only.** |

---

## 2. Safety tiers — `mewtwo/modules/hunt/safety.py`

Bug-bounty programs ban destructive testing. The `SafetyTier` enum (`safe` / `normal` /
`aggressive`) controls two things:

* **Destructive payloads** (`DROP TABLE`, `DELETE FROM`, `rm -rf`, …) are stripped by
  `filter_payloads()` unless the tier is `aggressive`. The SQLi check now routes its
  payloads through this filter — the old `'; DROP TABLE users--` no longer fires by default.
* **Aggressive-only checks** (`aggressive_only = True`, e.g. race conditions) are skipped by
  `allow_check()` unless the tier is `aggressive`.

```bash
mewtwo hunt run --tier safe          # non-mutating payloads only
mewtwo hunt run                      # normal (default) — destructive stripped
mewtwo hunt run --tier aggressive    # everything; authorised targets only
```

The runner sets `check.tier` on each check instance before calling `run()`.

---

## 3. Scope enforcement + throttle — `netguard.py`, `utils/throttle.py`

`ScopeRateLimitTransport` is an `httpx.AsyncBaseTransport` wrapper installed on the hunt
client. Because it sits at the transport layer, **every** request a check makes passes
through it:

* **Scope** — any request whose host is not in the workspace's in-scope patterns raises
  `OutOfScopeError` before it hits the wire. This is the hard guarantee that active hunting
  never touches an out-of-scope host. Disable only with `--no-scope-enforce`.
* **Rate limit** — an `AsyncRateLimiter` (token bucket) caps requests/second. Set per-run
  with `--rate` or globally via `MEWTWO_RATE_LIMIT`. `0` = unlimited.

---

## 4. Authenticated scanning

`config.build_auth()` turns a cookie string / bearer token / extra header (from CLI flags or
`MEWTWO_AUTH_*` env vars) into headers+cookies injected into every hunt request. Most
IDOR/authorization bugs only surface with a valid session.

```bash
mewtwo hunt run --auth-cookie 'session=abc; csrf=def'
mewtwo hunt run --auth-bearer eyJhbGci...
```

---

## 5. Recon additions

| Command | Module | Purpose |
|---------|--------|---------|
| `mewtwo recon favicon <url>` | `recon/favicon.py` | Shodan-compatible mmh3 favicon hash (pure-Python fallback, no hard dep) for infra pivoting. |
| `mewtwo recon params <url> [--save]` | `recon/param_miner.py` | Reflection-based hidden-parameter discovery; `--save` feeds them into surface mapping. |
| `mewtwo recon takeover` | `recon/dns_intel.py` | Resolves CNAMEs for alive subdomains and flags takeover-prone providers (needs `dnspython`). |
| `mewtwo hunt nuclei` | `hunt/nuclei.py` | Shells out to a local `nuclei` binary, imports JSONL results as findings with mapped severity. |

---

## 6. AI additions

| Command | Method | Purpose |
|---------|--------|---------|
| `mewtwo ai poc <finding_id>` | `AIClient.generate_poc` | Reproducible, **non-destructive** PoC (steps + curl + optional script). |
| `mewtwo ai dedup [--apply]` | `AIClient.cluster_findings` | Clusters duplicate findings across endpoints by root cause. |
| `mewtwo ai hunt <url> --yes` | `ai/agent.py` | Bounded agentic loop: Claude forms hypotheses and probes via a constrained `http_request` tool. Host-locked, scope-locked, non-destructive, step-budgeted. |

The agentic loop reuses the same scope/rate transport as the hunt and refuses destructive or
off-host requests inside the tool-execution step, so the model cannot escape the guardrails.

---

## 7. Resumable recon

`run_full_recon(resume=True)` records a checkpoint per step in a `recon_checkpoints` table and
skips steps already completed, so an interrupted recon re-runs without redoing finished work.
`mewtwo recon run --force` clears checkpoints and redoes everything.

---

## 8. Tests — `tests/`

`pytest` suite covering the pure logic: CVSS known-answer vectors, safety tiers, scope
transport + throttle, favicon murmur3 KATs, DNS provider matching, validators, JWT cracking,
and the new checks against mocked HTTP (`pytest-httpx`). Run with `pytest`.

> The CVSS test caught a real pre-existing bug: the calculator used Python's `round()` instead
> of the CVSS 3.1 *Roundup* function, scoring the canonical reflected-XSS vector 6.0 instead of
> the official 6.1. Fixed in `findings/cvss.py`.

---

## Needs API keys (not yet wired)

Shodan / Censys / VirusTotal / AlienVault OTX passive sources and GitHub/Google dorking all
require paid or key-gated APIs. They are intentionally left as a documented extension point
rather than shipped as untested stubs.
