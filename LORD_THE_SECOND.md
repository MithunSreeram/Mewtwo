# 📕 Lord the Second — The Definitive Mewtwo Codebase Guide

> A complete, file-by-file walkthrough of the **Mewtwo** AI-assisted bug bounty toolkit — what every file does, how data moves through the system, and why the architecture is shaped the way it is.

---

## Table of Contents

1. [What Mewtwo Is](#1-what-mewtwo-is)
2. [The 30-Second Mental Model](#2-the-30-second-mental-model)
3. [End-to-End Lifecycle](#3-end-to-end-lifecycle)
4. [Repository Map](#4-repository-map)
5. [Foundation Layer](#5-foundation-layer-project--config)
6. [Models Layer](#6-models-layer-mewtwomodels)
7. [Storage Layer](#7-storage-layer-mewtwostorage)
8. [Utilities Layer](#8-utilities-layer-mewtwoutils)
9. [The Root CLI](#9-the-root-cli-mewtwoclipy)
10. [Phase 1 — Recon](#10-phase-1--recon-modulesrecon)
11. [Phase 2 — Surface Mapping](#11-phase-2--surface-mapping-modulessurface)
12. [Phase 3 — Hunt](#12-phase-3--hunt-moduleshunt)
13. [Phase 4 — Findings](#13-phase-4--findings-modulesfindings)
14. [Phase 5 — Report](#14-phase-5--report-modulesreport)
15. [The AI Brain](#15-the-ai-brain-modulesai)
16. [Workspace Portability & TUI](#16-workspace-portability--tui)
17. [Documentation Set](#17-documentation-set-docs)
18. [External Tools & Fallbacks](#18-external-tools--fallbacks)
19. [Architecture Diagrams](#19-architecture-diagrams)
20. [Design Patterns Cheat Sheet](#20-design-patterns-cheat-sheet)

---

## 1. What Mewtwo Is

**Mewtwo** is a command-line bug bounty platform that takes a security researcher from a bare domain name all the way to a submitted, professional vulnerability report — with Claude AI woven into every phase for analysis, triage, and writing.

| Attribute | Value |
|---|---|
| Version | `0.1.0` |
| Language | Python ≥ 3.10 |
| CLI entry point | `mewtwo` → `mewtwo.cli:cli` |
| Storage | SQLite (one DB per workspace) |
| AI provider | Anthropic Claude (default model `claude-opus-4-5`) |
| Core stack | click · rich · httpx · pydantic · sqlite-utils · jinja2 |
| Optional extras | `pdf` (weasyprint) · `tui` (textual) · `dev` (pytest, ruff, mypy) |

**The core idea:** every phase writes structured data to SQLite, and every subsequent phase reads from it. This makes the workflow resumable, inspectable, and portable — you can stop after recon, come back a week later, and pick up at surface mapping with everything intact.

---

## 2. The 30-Second Mental Model

```
        YOU                MEWTWO                       CLAUDE
         │                    │                            │
   "scan example.com" ───────▶│                            │
         │              gather facts                       │
         │              (recon)                            │
         │                    │── "what's attackable?" ───▶│
         │                    │◀──── attack vectors ───────│
         │              fire checks                        │
         │              (hunt)                             │
         │                    │── "is this real?" ────────▶│
         │                    │◀──── triage verdict ───────│
         │              write report                       │
         │                    │── "draft this finding" ───▶│
         │                    │◀──── polished prose ───────│
         │◀──── report.pdf ───│                            │
```

Mewtwo does the **mechanical work** (network requests, parsing, persistence). Claude does the **judgment work** (prioritization, false-positive filtering, professional writing). SQLite is the **shared memory** between them.

---

## 3. End-to-End Lifecycle

```bash
mewtwo init "Acme Corp" --platform hackerone --domain acme.com   # 1. workspace
mewtwo scope add '*.acme.com' --type in                          # 2. scope
mewtwo recon run -d acme.com                                     # 3. recon
mewtwo surface map --ai                                          # 4. surface
mewtwo hunt run --ai-triage                                      # 5. hunt
mewtwo findings enrich 3                                         # 6. findings
mewtwo report generate --format pdf --ai                         # 7. report
mewtwo report submit 3 --h1-username me --h1-token xxx           # 8. submit
mewtwo export                                                    # 9. archive
```

| # | Phase | Command | Reads | Writes |
|---|---|---|---|---|
| 1 | Init | `init` | — | `targets`, DB, dirs |
| 2 | Scope | `scope add` | — | `scope` |
| 3 | Recon | `recon run` | `scope` | `subdomains`, `ports`, `technologies`, `urls`, `js_secrets` |
| 4 | Surface | `surface map` | recon tables | `attack_vectors` |
| 5 | Hunt | `hunt run` | `attack_vectors` | `findings` (DRAFT) + evidence files |
| 6 | Findings | `findings *` | `findings` | `findings` (enriched, CVSS, status) |
| 7 | Report | `report generate` | `findings` | report files |
| 8 | Submit | `report submit` | `findings` | external platform |
| 9 | Export | `export` | whole workspace | `.mewtwo` archive |

---

## 4. Repository Map

```
Mewtwo/
├── pyproject.toml                  # packaging, deps, entry point, extras
├── .env.example                    # configuration template
├── README.md                       # project intro
├── docs/                           # 9 hand-written design guides
│   ├── 01-architecture.md … 09-tui-workspace.md
└── mewtwo/
    ├── __init__.py                 # version/author
    ├── cli.py                      # ROOT CLI + workspace & scope commands
    ├── config.py                   # path resolution + settings
    ├── db.py                       # SQLite schema bootstrap
    ├── workspace_io.py             # export / import archives
    ├── tui.py                      # Textual dashboard (optional)
    ├── models/                     # Pydantic data shapes
    │   ├── target.py  finding.py  recon.py  surface.py  session.py
    ├── storage/                    # repository pattern over SQLite
    │   ├── base.py  targets.py  recon.py  surface.py  findings.py  sessions.py
    ├── utils/                      # cross-cutting helpers
    │   ├── console.py  validators.py  process.py  http.py  evidence.py
    └── modules/                    # the 6 functional phases
        ├── recon/    (cli, runner, subdomains, ports, tech, crawler, js_analyzer, wayback)
        ├── surface/  (cli, mapper, heuristics)
        ├── hunt/     (cli, runner, checks/*, payloads/*)
        ├── findings/ (cli, cvss)
        ├── report/   (cli, builder, renderer, submit, templates/*)
        └── ai/       (cli, client, prompts, tools)
```

---

## 5. Foundation Layer (Project & Config)

### `pyproject.toml`
The packaging manifest. Declares setuptools build, Python ≥3.10, all runtime deps (anthropic ≥0.40, click ≥8.1, rich ≥13, httpx ≥0.27, pydantic ≥2, sqlite-utils ≥3.35, jinja2 ≥3.1, python-dotenv ≥1.0), three optional extras (`pdf`, `tui`, `dev`), and the console script `mewtwo = "mewtwo.cli:cli"`.

### `.env.example`
Documents the six environment variables that tune the toolkit:

| Variable | Default | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | *(required)* | Unlocks all AI features |
| `MEWTWO_MODEL` | `claude-opus-4-5` | Which Claude model to call |
| `MEWTWO_PROXY` | *(none)* | Route traffic through Burp/ZAP |
| `MEWTWO_WORKSPACES_DIR` | `~/.mewtwo/workspaces` | Where workspaces live |
| `MEWTWO_TIMEOUT` | `30` | Per-request timeout (s) |
| `MEWTWO_CONCURRENCY` | `20` | Max parallel requests |

### `mewtwo/__init__.py`
Package marker — `__version__ = "0.1.0"`, `__author__ = "Mewtwo"`.

### `mewtwo/config.py` — the single source of truth for *where* and *what*
Every module asks this file for paths and settings, so nothing hardcodes locations.

```
Path resolution                          Settings accessors
─────────────────                        ──────────────────
mewtwo_home()        → ~/.mewtwo         anthropic_api_key() → str (raises if absent)
workspaces_dir()     → …/workspaces      model()             → str
workspace_path(slug) → …/workspaces/slug proxy()             → str | None
current_symlink()    → ~/.mewtwo/current timeout()           → int
active_workspace()   → resolved Path     concurrency()       → int
set_active_workspace(slug)
require_active_workspace() → Path (or raises click.UsageError)
db_path(ws) / reports_dir(ws) / evidence_dir(ws)
```

The **active workspace** is a symlink (`~/.mewtwo/current`). The `use` command just repoints it — an elegant way to keep a single global "current target."

### `mewtwo/db.py` — schema bootstrap
`get_db(db_path)` opens a sqlite-utils `Database` and calls `_ensure_schema()`, which **idempotently** creates ten tables. Safe to call on every open.

| Table | Role in the pipeline |
|---|---|
| `targets` | Program identity (name, slug, platform, program_url) |
| `scope` | In/out/informational patterns |
| `sessions` | Phase + JSON state snapshot |
| `subdomains` | Hostnames + liveness + IPs + discovery sources |
| `ports` | Open ports + service/version/banner |
| `technologies` | Detected stack + confidence |
| `urls` | Crawled & archived URLs + params + forms + headers |
| `js_secrets` | Secrets/endpoints scraped from JavaScript |
| `attack_vectors` | The "to-test" list, categorized + risk-rated |
| `findings` | Confirmed vulns + CVSS + evidence |

---

## 6. Models Layer (`mewtwo/models/`)

Pure Pydantic v2 shapes — no behavior, just validated structure. `__init__.py` re-exports them all.

### `target.py`
```
ScopeType    = IN_SCOPE | OUT_OF_SCOPE | INFORMATIONAL
ScopeEntry   = id, target_id, pattern, scope_type, notes
Target       = id, name, slug, platform, program_url, notes, created_at, updated_at
```

### `finding.py` — the richest model
```
Severity      = CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
FindingStatus = DRAFT → CONFIRMED → REPORTED → ACCEPTED | DUPLICATE | INFORMATIVE | CLOSED
CVSSVector    = AV, AC, PR, UI, S, C, I, A + score + vector_string   (CVSS 3.1)
Evidence      = kind(request|response|screenshot|note), content, caption
Finding       = id, target_id, title, vuln_class, severity, status, cvss,
                url, parameter, description, impact, reproduction_steps[],
                evidence[], remediation, references[], ai_generated,
                discovered_at, updated_at, tags[]
```
The `status` enum encodes the **finding lifecycle** — a draft from the hunter becomes confirmed, then reported, then resolved one of several ways.

### `recon.py`
```
Subdomain     = hostname, ip_addresses[], sources[], is_alive, status_code
Port          = host, port, protocol, service, version, banner
Technology    = host, name, version, category, confidence
DiscoveredURL = url, method, status_code, content_type, parameters[],
                forms[], interesting_headers, source(crawler|wayback)
JSSecret      = source_url, secret_type(api_key|jwt|endpoint|credential), value, confidence
```

### `surface.py`
```
VectorCategory = AUTHENTICATION | AUTHORIZATION | INJECTION | SSRF |
                 INFORMATION_DISCLOSURE | BUSINESS_LOGIC | CLIENT_SIDE | CONFIGURATION
AttackVector   = target_id, category, title, description, url, parameters[],
                 risk_rating(critical|high|medium|low), rationale,
                 source_recon_ids[], checked, finding_ids[]
```
`checked` is the bridge between surface and hunt — the hunter pulls unchecked vectors, runs them, and flips the flag.

### `session.py`
```
SessionPhase = RECON | SURFACE | HUNT | REPORTING
SessionState = recon_completed, surface_mapped, hunt_in_progress,
               last_recon_at, last_hunt_at,
               subdomain_count, url_count, attack_vector_count, finding_count
Session      = id, target_id, phase, state, notes, timestamps
```

---

## 7. Storage Layer (`mewtwo/storage/`)

A clean repository pattern that hides sqlite-utils behind typed methods.

### `base.py` — serialization backbone
```
_ser(value)                → list/dict→JSON, datetime→ISO, bool→0|1
_deserialize_row(row, json_fields, bool_fields)   → reverse
BaseRepository: get(id) · all(**where) · delete(id) · count(**where)
```
Every concrete repo declares its `json_fields` and `bool_fields`, and the base handles round-tripping automatically.

| Repository | Tables | Notable methods |
|---|---|---|
| `targets.py` → `TargetRepository` | targets | `upsert`, `get_by_slug`, `list_all` |
| `targets.py` → `ScopeRepository` | scope | `add`, `for_target`, `remove` |
| `recon.py` → `ReconRepository` | 5 recon tables | `upsert_subdomain/port/technology/url/js_secret` + `*_for(target_id)` getters |
| `surface.py` → `SurfaceRepository` | attack_vectors | `upsert`, `for_target(category=)`, `mark_checked` |
| `findings.py` → `FindingRepository` | findings | `upsert`, `for_target(severity=, status=)`, `update_status`, `update_fields` |
| `sessions.py` → `SessionRepository` | sessions | `upsert`, `for_target`, `update_phase` |

**Why upserts everywhere:** re-running any phase is safe and idempotent — no duplicate rows.

---

## 8. Utilities Layer (`mewtwo/utils/`)

| File | What it provides |
|---|---|
| `console.py` | Rich console singletons (`console`, `err_console`) + `success/warn/error/info` helpers + `severity_style()` color mapper. All output flows through here, never raw `print`. |
| `validators.py` | `is_valid_domain`, `is_valid_url`, `slugify`, `in_scope(url, patterns)` (fnmatch globbing), `extract_domain`. |
| `process.py` | Async subprocess wrappers: `run(*cmd)` → (rc, stdout, stderr); `stream_lines(*cmd)` async generator; `tool_available(name)` PATH check. Used to shell out to nmap/subfinder. |
| `http.py` | `make_client(...)` → preconfigured `httpx.AsyncClient` with Chrome-like UA, **SSL verification disabled** (bug bounty targets have bad certs), and proxy injection. |
| `evidence.py` | `format_request/format_response` render raw HTTP text (body capped at 4 KB); `save_evidence(...)` writes proof files under `<evidence_dir>/<finding_id>/`. This is how findings get their receipts. |

---

## 9. The Root CLI (`mewtwo/cli.py`)

The top-level click group. Implements workspace + scope commands and mounts the six phase sub-groups.

**Workspace commands**

| Command | What it does |
|---|---|
| `init <name>` | Slugify → create dirs → init DB → insert target row → set active |
| `use <name>` | Repoint the `current` symlink |
| `list` | Table of all workspaces (target, platform, finding count, DB size) |
| `status` | Progress panel for the active workspace (subdomains/alive/URLs/vectors/findings) |
| `export [name]` | Delegate to `workspace_io.export_workspace` |
| `import <archive>` | Delegate to `workspace_io.import_workspace` |
| `dashboard` | Launch the Textual TUI (needs `tui` extra) |

**Scope sub-group** (`mewtwo scope`)

| Command | What it does |
|---|---|
| `scope add <pattern> --type in\|out\|info` | Insert scope entry |
| `scope remove <pattern>` | Delete entry |
| `scope list` | Color-coded listing |

**Mounted sub-groups:** `recon`, `surface`, `hunt`, `findings`, `report`, `ai`.

---

## 10. Phase 1 — Recon (`modules/recon/`)

### `cli.py` — the recon command surface
| Command | Purpose |
|---|---|
| `recon run` | Full pipeline (`--domain`, `--only`, `--passive-only`, `--no-ai`) |
| `recon subdomains -d <domain>` | Enumeration only |
| `recon ports <host>` | nmap scan (`--top-ports`) |
| `recon tech <url>` | Fingerprint one URL |
| `recon crawl <url>` | BFS crawl (`--depth`, `--scope-only`) |
| `recon js <url>` | Analyze JavaScript |
| `recon wayback -d <domain>` | Harvest archived URLs |
| `recon show --type …` | Display stored results |

### `runner.py` — the orchestrator
```
run_full_recon(target, db_path, scope_patterns, steps, passive_only, use_ai):
   subdomains → ports → tech → crawl → wayback → js
   each step persists via ReconRepository, returns a summary count dict
```

### `subdomains.py`
```
enumerate_passive()  → crt.sh (cert transparency) + HackerTarget API
enumerate_active()   → subfinder subprocess (if installed & not passive-only)
probe_alive()        → try https:// then http:// (8s), set is_alive + status_code
run_subdomain_enum() → combine + probe concurrently (semaphore=30) → list[Subdomain]
```

### `ports.py`
`scan_ports(host, top_ports)` shells out to `nmap -sV --top-ports N -oX -`, parses the XML, returns `list[Port]`. No-ops gracefully if nmap is missing.

### `tech.py`
HTTP-only fingerprinting (no browser). `_SIGNATURES` matches response headers (Server, X-Powered-By…) for Apache/Nginx/PHP/ASP.NET/etc.; `_BODY_SIGNATURES` matches HTML body for WordPress/React/Angular/jQuery/etc. Dedupes by name → `list[Technology]` with confidence.

### `crawler.py`
Async BFS crawler:
```
crawl(seed, depth=3, scope_patterns, max_urls=500, concurrency=15):
   pop URL → skip if visited/over-depth/over-limit/bad-extension/out-of-scope
           → GET → extract links (href/src/action) → parse query params + <form> inputs
           → capture interesting headers (Authorization, X-API-Key, Set-Cookie…)
           → yield DiscoveredURL → enqueue children at depth+1
```

### `js_analyzer.py`
Downloads JS and regex-scans for **13 secret types**: `api_key`, `aws_key` (AKIA…), `google_api` (AIza…), `stripe_key` (sk_live/pk_live), `jwt` (eyJ…), `private_key`, `password`, `token`, `endpoint`, `internal_url`, `slack_webhook`, `github_token` (ghp_…), `mailchimp`.
```
analyze_page_js(page) → extract <script src> + inline JS → analyze up to 20 files
analyze_js_file(js)   → run all patterns → yield JSSecret(confidence)
```

### `wayback.py`
Queries the Wayback CDX API (`web.archive.org/cdx/search/cdx`), dedupes by URL key, filters to HTTP 200, drops binary/media extensions, parses timestamps → `list[DiscoveredURL]` with `source="wayback"`.

---

## 11. Phase 2 — Surface Mapping (`modules/surface/`)

Turns raw recon facts into a **prioritized, categorized to-test list**.

### `cli.py`
| Command | Purpose |
|---|---|
| `surface map [--ai]` | Heuristics + optional AI expansion |
| `surface show` | List vectors (`--category`, `--risk` filters) |
| `surface add` | Manually create a vector |
| `surface note <id> <text>` | Append note to a vector |

### `mapper.py` — orchestrator
```
run_surface_map(target_id, db_path, use_ai):
   load recon (subdomains, techs, urls, js_secrets)
   → heuristics.map_from_recon()           → deterministic vectors
   → if use_ai: AIClient.expand_attack_surface()  → chained/business-logic vectors
   → SurfaceRepository.upsert() each
```

### `heuristics.py` — deterministic pattern matching
Four sub-checkers feed a deduped (by category+url) vector list:

**`_check_urls`**
| Signal | Category → Risk |
|---|---|
| 401/403 response | AUTHORIZATION → medium |
| login/signin/oauth/saml | AUTHENTICATION → high |
| admin/dashboard/control-panel | AUTHORIZATION → high |
| upload/file=/attachment | INJECTION → high |
| `?redirect/return/next/url=` | CLIENT_SIDE (open redirect) → medium |
| `?id/user_id/account_id=` | AUTHORIZATION (IDOR) → high |
| `?url/uri/path/src=` | SSRF → high |
| `?search/query/q/filter=` | INJECTION (SQLi) → medium |
| `ACAO: *` | CONFIGURATION (CORS) → low |

**`_check_technologies`** → WordPress (xmlrpc, REST, plugins), Swagger/GraphQL (doc & introspection exposure), missing CSP.
**`_check_js_secrets`** → exposed keys/JWTs = HIGH; hidden endpoints = LOW.
**`_check_subdomains`** → interesting names (dev/staging/admin/api/vpn/jenkins/grafana/kibana…) = AUTHORIZATION priv-esc.

---

## 12. Phase 3 — Hunt (`modules/hunt/`)

The active testing engine: takes attack vectors, fires checks, produces draft findings with evidence.

### `cli.py`
| Command | Purpose |
|---|---|
| `hunt run` | Run checks (`--category`, `--vector-id`, `--checks`, `--no-ai`) |
| `hunt checks` | List all available checks |
| `hunt payload <class>` | Show/AI-generate payloads |
| `hunt ask <question>` | AI hunting assistant |

### `runner.py` — the dispatcher
```
run_hunt(target_id, db_path, evidence_dir, category_filter, vector_id, check_names, use_ai):
   select unchecked vectors
   for each vector:
     pick checks whose applicable_categories include vector.category
     run them concurrently (httpx, 15s timeout)
     for each FindingDraft:
       if use_ai → AIClient.triage_finding() (is_finding? severity? confidence?)
       save_evidence() → raw HTTP to disk
       FindingRepository.upsert(status=DRAFT)
     mark_checked(vector)
```

### `checks/base.py` — the contract
```
FindingDraft = title, vuln_class, severity, url, parameter, description,
               evidence[], references[], raw_request, raw_response
BaseCheck    = name, description, vuln_class, references, applicable_categories
               async run(vector, client, ai) → list[FindingDraft]
               _evidence_snippet(req, resp)
```
`__init__.py` exposes `ALL_CHECKS` — eleven check instances.

### The eleven checks

| Check | File | Categories | Technique (summary) |
|---|---|---|---|
| **XSS** | `xss.py` | client_side, injection | 7 built-in payloads (+`payloads/xss.txt`); inject into first 5 params; flag if payload reflects **unencoded** |
| **SQLi** | `sqli.py` | injection | Error-based (`'`, `OR 1=1--`, error-pattern match) + boolean-blind (true/false length delta > 200 B) |
| **IDOR** | `idor.py` | authorization | Mutate id-like params with `1,2,0,999999,admin,../1`; 200 + body >100 B = candidate; AI-triageable |
| **SSRF** | `ssrf.py` | ssrf | 6 payloads (AWS IMDS, GCP, Azure, Alibaba, localhost, file://, dict://); match metadata signatures |
| **Auth** | `auth.py` | authentication | Brute-force protection probe (5 fails → 429?) + JWT `alg:none` confusion |
| **CORS** | `cors.py` | configuration, authorization | Test `evil.com` / `null` / reflected origin × ACAC; severity scales with credentialed-ness |
| **Open Redirect** | `open_redirect.py` | client_side | 8 bypass payloads; flag 3xx with `evil.com` in Location |
| **Info Disclosure** | `info_disclosure.py` | info_disclosure, config, authn, authz | Probe 32 sensitive paths (`.env`, `.git/config`, `/actuator`, swagger…) + stack-trace regex |
| **Rate Limit** | `rate_limit.py` | authn, authz, config | 15 rapid hits to login-ish paths; ≥10 succeed w/o 429 = missing throttle |
| **Path Traversal** | `path_traversal.py` | injection, config, info_disc | 10 payloads (`../`, encoded, double-encoded, Windows) on file-ish params; match `root:`/win.ini |
| **XXE** | `xxe.py` | injection, config | XML endpoints only; file-read + error-based + SSRF payloads |

### `payloads/`
Static wordlists loaded at runtime: `xss.txt`, `sqli.txt`, `ssrf.txt` (one payload per line).

---

## 13. Phase 4 — Findings (`modules/findings/`)

Manages the lifecycle of a discovered vuln from draft to report-ready.

### `cli.py`
| Command | Purpose |
|---|---|
| `findings add` | Interactive create |
| `findings list` | Filter by `--severity/--status/--vuln-class` |
| `findings show <id>` | Full markdown detail panel |
| `findings status <id> <state>` | Transition lifecycle status |
| `findings cvss <id>` | Interactive CVSS 3.1 calculator |
| `findings enrich <id>` | AI drafts description/impact/steps/remediation |
| `findings attach <id> <file>` | Attach screenshot/PoC/Burp export |
| `findings evidence <id>` | Show captures + attachments |
| `findings delete <id>` | Remove finding |

### `cvss.py` — scoring
```
calculate_cvss(vector) → 0.0–10.0   (full CVSS 3.1 base formula:
                         AV/AC/PR/UI/S/C/I/A weights, scope-aware PR)
score_to_severity(s)   → ≥9 CRITICAL · ≥7 HIGH · ≥4 MEDIUM · >0 LOW · else INFO
interactive_cvss()     → click menu prompts for all 8 metrics → CVSSVector
```

---

## 14. Phase 5 — Report (`modules/report/`)

Transforms findings into deliverables and pushes them to platforms.

### `cli.py`
| Command | Purpose |
|---|---|
| `report generate` | `--format md\|html\|pdf\|all`, `--include`, `--no-ai` |
| `report pdf` | PDF only (weasyprint) |
| `report preview` | Terminal markdown preview |
| `report export <id>` | Single-finding standalone report |
| `report submit <id>` | Push to HackerOne/Bugcrowd (`--dry-run` supported) |

### `builder.py` — context assembly
```
build_report_context(db_path, include_statuses, use_ai):
   load target + findings (filtered) → sort by severity (critical first)
   if use_ai: enrich_finding() per finding + write_executive_summary()
   else: _default_exec_summary()
   → {target, findings, executive_summary, report_date, counts}
```

### `renderer.py` — formatting
```
render_markdown(ctx) → report.md.j2
render_html(ctx)     → report.html.j2 (embedded severity-colored CSS)
render_pdf(ctx, out) → render_html → weasyprint.write_pdf  (needs libpango/libglib)
```

### `templates/`
- `report.md.j2` — title → exec summary → findings summary table → per-severity sections (description/impact/steps/remediation/references).
- `report.html.j2` — same structure, colored severity badges, print-friendly page breaks.

### `submit.py` — platform APIs
```
HackerOneClient  → POST /v1/reports (Basic auth username:token)
                   severity rating mapping; returns report id + URL
BugcrowdClient   → POST /v4/submissions (Bearer token)
                   severity→priority (crit=1…info=5); vuln_class→VRT id
_build_h1_report_body / _build_bc_report_body  → platform-specific markdown
_vuln_class_to_vrt  → maps classes to Bugcrowd taxonomy
```

---

## 15. The AI Brain (`modules/ai/`)

Claude integration, used both as standalone commands and as a service called by other phases.

### `cli.py`
| Command | Purpose |
|---|---|
| `ai ask <q>` | One-shot Q&A (`--context recon\|surface\|findings\|all`, `--no-stream`) |
| `ai chat` | Interactive multi-turn session w/ workspace context |
| `ai analyze` | Full-workspace insight pass |
| `ai chains` | Find multi-finding attack chains (`--severity`) |
| `ai payloads <class>` | Tech-aware payload generation (`--url`, `--param`) |

### `client.py` — the Anthropic wrapper
**Primitives**
```
complete(system, messages, tools, max_tokens)      → text | tool input
stream(system, messages, max_tokens)               → async text deltas
complete_with_tool(system, messages, tool, …)      → forced tool input dict
workspace_context_snippet(db_path)                 → compact JSON of counts
```
**High-level task methods** (each pairs a prompt + a tool):

| Method | Tool | Returns |
|---|---|---|
| `analyze_recon` | ATTACK_VECTORS_TOOL | `list[AttackVector]` |
| `expand_attack_surface` | ATTACK_VECTORS_TOOL | `list[AttackVector]` |
| `triage_finding` | TRIAGE_TOOL | `{is_finding, severity, confidence, reason}` |
| `enrich_finding` | ENRICHMENT_TOOL | `{description, impact, steps, remediation, refs}` |
| `analyze_attack_chains` | ATTACK_CHAIN_TOOL | `list[chain]` |
| `generate_personalised_payloads` | PERSONALISED_PAYLOAD_TOOL | `list[{payload, technique, rationale, placement}]` |
| `generate_payloads` | *(text)* | `list[str]` |
| `write_executive_summary` | *(text)* | `str` (200–350 words) |
| `ask` | *(text/stream)* | `str` / async stream |

### `prompts.py` — centralized prompt library
A `_PURPLE_TEAM_PERSONA` (senior red/blue engineer, low-false-positive bias) anchors nine system prompts (`recon_analysis_system`, `surface_expansion_system`, `triage_system`, `payload_system`, `enrichment_system`, `exec_summary_system`, `attack_chain_system`, `personalised_payload_system`, `ask_system`), each with a paired `*_user()` data formatter. Keeping prompts here means no f-strings scattered across call sites.

### `tools.py` — structured-output schemas
Six Claude tool definitions force reliable JSON: `ATTACK_VECTORS_TOOL`, `TRIAGE_TOOL`, `ENRICHMENT_TOOL`, `ATTACK_CHAIN_TOOL`, `PERSONALISED_PAYLOAD_TOOL`, `CVSS_TOOL`.

---

## 16. Workspace Portability & TUI

### `mewtwo/workspace_io.py`
```
export_workspace(ws, output) → tar.gz (.mewtwo):
   mewtwo-export/{manifest.json, mewtwo.db, reports/, evidence/}
   manifest = {mewtwo_version, workspace_slug, exported_at, file list}

import_workspace(archive, workspaces_dir, activate):
   read manifest → refuse if slug exists (FileExistsError)
   extract db + reports + evidence → optionally set active → return slug
```

### `mewtwo/tui.py` (optional, `textual`)
A `StatCard` widget + `MewtwoApp` with four tabs:

| Tab | Shows |
|---|---|
| Overview | Stat cards (subdomains/alive/URLs/vectors/findings/critical) + recent findings |
| Recon | Subdomains table |
| Attack Surface | Vectors table |
| Hunt | All findings table |

Keys: `r` refresh, `q` quit. Reads straight from the active workspace DB.

---

## 17. Documentation Set (`docs/`)

Nine hand-written guides mirroring the architecture:

| File | Covers |
|---|---|
| `01-architecture.md` | System design & data flow |
| `02-workspace.md` | Workspace + scope lifecycle |
| `03-recon.md` | Recon internals & tool deps |
| `04-surface.md` | Heuristics + AI expansion |
| `05-hunt.md` | Checks & evidence |
| `06-findings.md` | Lifecycle, CVSS, enrichment |
| `07-ai.md` | Claude tools & prompts |
| `08-report.md` | Formats & submission |
| `09-tui-workspace.md` | Dashboard usage |

---

## 18. External Tools & Fallbacks

| Tool | Used by | If missing |
|---|---|---|
| `nmap` | `recon/ports.py` | Port scan skipped |
| `subfinder` | `recon/subdomains.py` | Passive enumeration only |
| `weasyprint` | `report/renderer.py` | PDF disabled (MD/HTML still work) |
| `textual` | `tui.py` | Dashboard disabled |

Graceful degradation throughout — Mewtwo never hard-fails because an optional binary is absent.

---

## 19. Architecture Diagrams

### Layered architecture
```
┌─────────────────────────────────────────────────────────────┐
│                          CLI LAYER                            │
│   cli.py  +  modules/*/cli.py  (click groups, user-facing)    │
├─────────────────────────────────────────────────────────────┤
│                       ORCHESTRATION LAYER                     │
│   recon/runner · surface/mapper · hunt/runner · report/builder│
├──────────────────────────────┬──────────────────────────────┤
│        DOMAIN LOGIC           │          AI SERVICE           │
│  recon/* surface/heuristics   │   ai/client · prompts · tools │
│  hunt/checks/* findings/cvss  │   (Claude, cross-cutting)     │
├──────────────────────────────┴──────────────────────────────┤
│                         STORAGE LAYER                         │
│        storage/*  (repository pattern over sqlite-utils)      │
├─────────────────────────────────────────────────────────────┤
│                       FOUNDATION LAYER                        │
│      config · db · models/* · utils/* · workspace_io          │
└─────────────────────────────────────────────────────────────┘
```

### Data flow through the pipeline
```
  scope ─┐
         ▼
  ┌────────────┐   subdomains/ports/    ┌──────────────┐  attack_     ┌────────────┐
  │   RECON    │──▶ tech/urls/js ──────▶│   SURFACE    │──▶ vectors ──▶│    HUNT    │
  │ (gather)   │   (recon tables)       │  (heuristics │  (checked    │ (11 checks)│
  └────────────┘                        │   + AI)      │   flag)      └─────┬──────┘
        ▲                               └──────────────┘                    │ DRAFT
        │                                       ▲                           ▼ findings
        │                                       │                    ┌────────────┐
   ┌────┴─────┐                                 │ "what's            │  FINDINGS  │
   │  CLAUDE  │◀────────────────────────────────┘  attackable?"      │ CVSS+enrich│
   │ (ai/*)   │◀───── "is this real?" (triage) ────────────────────  └─────┬──────┘
   │          │◀───── "draft this finding" (enrich) ◀─────────────┐        │
   └──────────┘◀───── "executive summary" ◀──────────────┐        │        ▼
                                                          │  ┌─────┴────────────┐
                                                          └──│      REPORT       │
                                                             │ MD/HTML/PDF + API │
                                                             └───────────────────┘
                          (all phases read/write SQLite via storage/)
```

---

## 20. Design Patterns Cheat Sheet

| Pattern | Location | Why it matters |
|---|---|---|
| **Repository pattern** | `storage/` | Business logic never touches raw SQL |
| **Pydantic models** | `models/` | Validation + type safety at boundaries |
| **Click command groups** | `*/cli.py` | Composable, discoverable CLI |
| **Async + httpx** | all network I/O | High concurrency, no threads |
| **Claude tool use** | `ai/tools.py` | Forces reliable structured JSON from the LLM |
| **Streaming** | `ai/client.py` | Live markdown rendering in the terminal |
| **Active-workspace symlink** | `config.py` | One global pointer; `use` swaps it atomically |
| **Idempotent upserts** | `storage/` | Re-run any phase safely, no duplicates |
| **Evidence capture** | `utils/evidence.py` + `hunt/runner.py` | Every finding carries reproducible proof |
| **Centralized prompts** | `ai/prompts.py` | Prompt engineering lives in one auditable place |
| **Graceful degradation** | recon/report/tui | Optional tools never cause hard failures |

---

*Generated as a complete reference to the Mewtwo codebase — every file, its responsibility, and how data flows from a bare domain to a submitted report.*
