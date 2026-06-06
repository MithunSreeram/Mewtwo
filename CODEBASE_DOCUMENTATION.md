# Mewtwo — Complete Codebase Documentation

**Mewtwo** is an AI-assisted bug bounty toolkit that provides an end-to-end workflow: from reconnaissance through vulnerability hunting to professional report generation, with Claude AI integrated throughout for intelligent analysis, triage, and enrichment.

- **Version:** 0.1.0
- **Python:** ≥3.10
- **Entry point:** `mewtwo` CLI (`mewtwo.cli:cli`)
- **Core dependencies:** anthropic, click, rich, httpx, pydantic, sqlite-utils, jinja2, python-dotenv

---

## Overall System Flow

```
mewtwo init                    # 1. Create workspace (SQLite DB + directories)
mewtwo scope add               # 2. Define in/out-of-scope patterns
mewtwo recon run               # 3. Enumerate subdomains, ports, tech, URLs, JS secrets
mewtwo surface map             # 4. Map recon data → attack vectors (heuristics + AI)
mewtwo hunt run                # 5. Fire automated checks (XSS, SQLi, IDOR, SSRF, …)
mewtwo findings enrich         # 6. AI drafts description, impact, remediation
mewtwo report generate         # 7. Build MD / HTML / PDF report
mewtwo report submit           # 8. Push to HackerOne or Bugcrowd API
mewtwo export                  # 9. Archive workspace for portability
```

Data flows **downward**: recon feeds surface mapping, which feeds hunting, which feeds findings, which feeds reporting. Each phase persists its results to SQLite and the next phase reads from there.

---

## File-by-File Reference

---

### `pyproject.toml`

Project metadata and dependency declarations.

| Field | Value |
|---|---|
| Build system | setuptools |
| Entry point | `mewtwo = "mewtwo.cli:cli"` |
| Extras | `pdf` (weasyprint), `tui` (textual), `dev` (pytest, ruff, mypy) |

Key dependency versions: anthropic ≥0.40.0, click ≥8.1, rich ≥13.0, httpx ≥0.27, pydantic ≥2.0, sqlite-utils ≥3.35, jinja2 ≥3.1.

---

### `.env.example`

Template showing every configurable environment variable:

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required for all AI features |
| `MEWTWO_MODEL` | `claude-opus-4-5` | Claude model used |
| `MEWTWO_PROXY` | — | HTTP proxy (e.g. Burp Suite) |
| `MEWTWO_WORKSPACES_DIR` | `~/.mewtwo/workspaces` | Override workspace storage path |
| `MEWTWO_TIMEOUT` | `30` | HTTP request timeout in seconds |
| `MEWTWO_CONCURRENCY` | `20` | Max parallel HTTP requests |

---

### `mewtwo/__init__.py`

Package marker. Exports `__version__ = "0.1.0"` and `__author__ = "Mewtwo"`.

---

### `mewtwo/config.py`

**Purpose:** Centralised path resolution and settings access. Everything that needs to know *where* things live or *what* the current settings are calls this module.

**Key functions:**

| Function | Returns | Description |
|---|---|---|
| `mewtwo_home()` | `Path` | `~/.mewtwo` global config directory |
| `workspaces_dir()` | `Path` | Workspace root (overridable via env) |
| `workspace_path(slug)` | `Path` | Path to one named workspace |
| `current_symlink()` | `Path` | `~/.mewtwo/current` symlink to active workspace |
| `active_workspace()` | `Path \| None` | Resolves symlink; `None` if not set |
| `set_active_workspace(slug)` | `None` | Atomically repoints the symlink |
| `require_active_workspace()` | `Path` | Like above but raises `click.UsageError` |
| `db_path(ws)` | `Path` | `<ws>/mewtwo.db` |
| `reports_dir(ws)` | `Path` | `<ws>/reports/` |
| `evidence_dir(ws)` | `Path` | `<ws>/evidence/` |
| `anthropic_api_key()` | `str` | From env; raises if missing |
| `model()` | `str` | Claude model name |
| `proxy()` | `str \| None` | Optional proxy URL |
| `timeout()` | `int` | Request timeout seconds |
| `concurrency()` | `int` | Parallel request limit |

---

### `mewtwo/db.py`

**Purpose:** Bootstraps and migrates the SQLite database schema. Called once per workspace creation and on every open (idempotent).

**Flow:**
```
get_db(db_path)
  └─ sqlite_utils.Database(db_path)
  └─ _ensure_schema(db)
       └─ Creates tables if not exist (using sqlite-utils .create())
```

**Tables created:**

| Table | Key columns | Purpose |
|---|---|---|
| `targets` | id, name, slug, platform, program_url | Bug bounty program metadata |
| `scope` | pattern, scope_type, target_id | In/out-of-scope domain patterns |
| `sessions` | phase, state_json, target_id | Workflow phase tracking |
| `subdomains` | hostname, is_alive, ip_addresses_json, sources_json | Enumerated hostnames |
| `ports` | host, port, protocol, service, version, banner | Open port scan results |
| `technologies` | name, version, category, confidence, host | Detected tech stack |
| `urls` | url, method, status_code, parameters_json, forms_json | Crawled/harvested URLs |
| `js_secrets` | secret_type, value, confidence, source_url | Secrets found in JS files |
| `attack_vectors` | category, title, url, risk_rating, checked | Mapped attack surface entries |
| `findings` | title, severity, status, cvss_json, evidence_json | Confirmed vulnerabilities |

---

## Models Layer (`mewtwo/models/`)

Pydantic v2 models providing type-safe data structures. No DB logic here — pure data shape definitions.

---

### `mewtwo/models/__init__.py`

Re-exports all models for convenient `from mewtwo.models import Finding` imports.

---

### `mewtwo/models/target.py`

```
ScopeType (enum)
  IN_SCOPE | OUT_OF_SCOPE | INFORMATIONAL

ScopeEntry
  id, target_id, pattern: str, scope_type: ScopeType, notes: str

Target
  id, name, slug, platform, program_url, notes, created_at, updated_at
```

---

### `mewtwo/models/finding.py`

The most complex model — represents a discovered vulnerability.

```
Severity (enum)
  CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL

FindingStatus (enum)
  DRAFT → CONFIRMED → REPORTED → ACCEPTED | DUPLICATE | INFORMATIVE | CLOSED

CVSSVector
  attack_vector, attack_complexity, privileges_required, user_interaction
  scope, confidentiality, integrity, availability
  score: float, vector_string: str

Evidence
  kind: request | response | screenshot | note
  content: str
  caption: str

Finding
  id, target_id, title, vuln_class, severity, status
  cvss: CVSSVector | None
  url, parameter, description, impact
  reproduction_steps: list[str]
  evidence: list[Evidence]
  remediation, references: list[str]
  ai_generated: bool
  discovered_at, updated_at, tags: list[str]
```

---

### `mewtwo/models/recon.py`

Data shapes for all recon output:

```
Subdomain       — hostname, ip_addresses, sources, is_alive, status_code
Port            — host, port, protocol, service, version, banner
Technology      — host, name, version, category, confidence (0.0–1.0)
DiscoveredURL   — url, method, status_code, content_type, parameters,
                  forms, interesting_headers, source (crawler | wayback)
JSSecret        — source_url, secret_type (api_key/jwt/endpoint/credential),
                  value, confidence
```

---

### `mewtwo/models/surface.py`

```
VectorCategory (enum)
  AUTHENTICATION | AUTHORIZATION | INJECTION | SSRF
  INFORMATION_DISCLOSURE | BUSINESS_LOGIC | CLIENT_SIDE | CONFIGURATION

AttackVector
  target_id, category, title, description, url
  parameters: list[str]
  risk_rating: critical | high | medium | low
  rationale: str
  source_recon_ids: list[int]
  checked: bool
  finding_ids: list[int]
```

---

### `mewtwo/models/session.py`

```
SessionPhase (enum)
  RECON | SURFACE | HUNT | REPORTING

SessionState
  recon_completed, surface_mapped, hunt_in_progress: bool
  last_recon_at, last_hunt_at: datetime | None
  subdomain_count, url_count, attack_vector_count, finding_count: int

Session
  id, target_id, phase, state: SessionState, notes, created_at, updated_at
```

---

## Storage Layer (`mewtwo/storage/`)

Repository pattern on top of sqlite-utils. Each repository handles one or more related tables.

---

### `mewtwo/storage/base.py`

**Purpose:** Shared serialisation/deserialisation helpers used by all repositories.

```
_ser(value)
  list/dict → JSON string
  datetime  → ISO 8601 string
  bool      → 0 | 1

_deserialize_row(row, json_fields, bool_fields)
  Inverse of _ser: parses JSON strings back, bools back to Python bool

BaseRepository
  table_name: str
  json_fields: list[str]
  bool_fields: list[str]
  ── get(id)           → single row dict | None
  ── all(**where)      → list[dict]
  ── delete(id)        → None
  ── count(**where)    → int
```

---

### `mewtwo/storage/targets.py`

```
TargetRepository (BaseRepository)
  upsert(target: Target)      → saved id
  get_by_slug(slug)           → dict | None
  list_all()                  → list[dict]

ScopeRepository (BaseRepository)
  add(entry: ScopeEntry)      → saved id
  for_target(target_id)       → list[dict]
  remove(target_id, pattern)  → None
```

---

### `mewtwo/storage/sessions.py`

```
SessionRepository (BaseRepository)
  upsert(session: Session)             → saved id
  for_target(target_id)               → latest session dict | None
  update_phase(session_id, phase)     → None
```

---

### `mewtwo/storage/recon.py`

```
ReconRepository
  upsert_subdomain(target_id, sub: Subdomain)
  upsert_port(target_id, port: Port)
  upsert_technology(target_id, tech: Technology)
  upsert_url(target_id, url: DiscoveredURL)
  upsert_js_secret(target_id, secret: JSSecret)

  subdomains_for(target_id)   → list[dict]
  ports_for(target_id)        → list[dict]
  techs_for(target_id)        → list[dict]
  urls_for(target_id)         → list[dict]
  js_secrets_for(target_id)   → list[dict]
```

All upserts use sqlite-utils `.upsert()` so re-running recon won't create duplicates.

---

### `mewtwo/storage/surface.py`

```
SurfaceRepository (BaseRepository)
  upsert(vector: AttackVector)                    → saved id
  for_target(target_id, category=None)            → list[dict]
  mark_checked(vector_id)                         → None
  _deserialize(row)                               → dict (json fields parsed)
```

---

### `mewtwo/storage/findings.py`

```
FindingRepository (BaseRepository)
  upsert(finding: Finding)                         → saved id
  for_target(target_id, severity=None, status=None) → list[dict]
  update_status(finding_id, status)                → None
  update_fields(finding_id, **fields)              → None
```

JSON fields handled: reproduction_steps, evidence, cvss, references, tags.

---

## Utilities (`mewtwo/utils/`)

---

### `mewtwo/utils/console.py`

Rich-based output helpers. All modules import from here instead of using `print`.

```
console         — Rich Console (stdout, custom theme)
err_console     — Rich Console (stderr)

success(msg)    — green ✓
warn(msg)       — yellow ⚠
error(msg)      — red ✗
info(msg)       — blue ℹ
severity_style(sev) → str color code ("bold red", "yellow", …)
```

---

### `mewtwo/utils/validators.py`

Input validation and string utilities:

```
is_valid_domain(domain)          → bool  (regex: labels + TLD)
is_valid_url(url)                → bool  (urllib.parse check)
slugify(name)                    → str   (lowercase, spaces→hyphens, strip special)
in_scope(url, scope_patterns)    → bool  (fnmatch glob against patterns list)
extract_domain(url)              → str   (netloc from urllib.parse)
```

---

### `mewtwo/utils/process.py`

Async subprocess helpers for calling external tools (nmap, subfinder):

```
async run(*cmd, timeout=60, check=False)
  → (returncode: int, stdout: str, stderr: str)

async stream_lines(*cmd, timeout=120)
  → AsyncGenerator[str]   (yields each stdout line)

tool_available(name)
  → bool   (shutil.which check)
```

---

### `mewtwo/utils/http.py`

Factory for pre-configured httpx async clients:

```
make_client(headers={}, proxy=None, timeout=30, follow_redirects=True)
  → httpx.AsyncClient
  — User-Agent: Chrome-like Mozilla string
  — SSL verification disabled (bug bounty targets often have cert issues)
  — Proxy injection for routing through Burp Suite
```

---

### `mewtwo/utils/evidence.py`

HTTP evidence capture for storing alongside findings:

```
format_request(request: httpx.Request)   → str   (raw HTTP/1.1 request text)
format_response(response: httpx.Response) → str  (raw response, body capped at 4 KB)

save_evidence(evidence_dir, finding_id, label, raw_req, raw_resp, notes)
  — Writes <evidence_dir>/<finding_id>/<label>.txt to disk
  — Returns Evidence model

save_evidence_from_httpx(evidence_dir, finding_id, label, request, response, notes)
  — Convenience wrapper: formats then saves
```

---

## Main CLI (`mewtwo/cli.py`)

**Purpose:** Root Click command group. Registers all sub-groups and implements workspace-level commands.

### Workspace Commands

| Command | Description |
|---|---|
| `mewtwo init <name>` | Create workspace: slugify name, create directories, init DB, create target row, set as active |
| `mewtwo use <name>` | Switch active workspace symlink |
| `mewtwo list` | Table of all workspaces: target name, platform, finding count, DB size |
| `mewtwo status` | Progress panel for active workspace: subdomains/alive/URLs/vectors/findings breakdown |
| `mewtwo export [name]` | Pack to `.mewtwo` archive (calls `workspace_io.export_workspace`) |
| `mewtwo import <archive>` | Restore from archive (calls `workspace_io.import_workspace`) |
| `mewtwo dashboard` | Launch Textual TUI (requires `textual` extra) |

### Scope Commands (`mewtwo scope`)

| Command | Description |
|---|---|
| `scope add <pattern>` | Add pattern with `--type in\|out\|info` (default: in_scope) |
| `scope remove <pattern>` | Delete scope entry |
| `scope list` | Display all scope entries coloured by type |

### Registered Sub-groups

The CLI composes by adding these Click groups:
- `recon` → `modules/recon/cli.py`
- `surface` → `modules/surface/cli.py`
- `hunt` → `modules/hunt/cli.py`
- `findings` → `modules/findings/cli.py`
- `report` → `modules/report/cli.py`
- `ai` → `modules/ai/cli.py`

---

## Recon Module (`mewtwo/modules/recon/`)

### `recon/cli.py`

Click commands for the recon phase:

| Command | Options | Description |
|---|---|---|
| `recon run` | `--domain`, `--only`, `--passive-only`, `--no-ai` | Full pipeline orchestration |
| `recon subdomains -d <domain>` | — | Enumerate subdomains only |
| `recon ports <host>` | `--top-ports` (default 1000) | Port scan one host |
| `recon tech <url>` | — | Fingerprint one URL |
| `recon crawl <url>` | `--depth`, `--scope-only` | BFS crawl |
| `recon js <url>` | — | JS analysis on page or JS file |
| `recon wayback -d <domain>` | — | Wayback Machine harvest |
| `recon show` | `--type all\|subdomains\|ports\|tech\|urls\|js` | Display stored results |

---

### `recon/runner.py`

**Purpose:** Orchestrates the full recon pipeline in the correct order.

**Flow:**
```
run_full_recon(target, db_path, scope_patterns, steps, passive_only, use_ai)
  1. subdomains  → subdomains.run_subdomain_enum()
                 → ReconRepository.upsert_subdomain() for each
  2. ports       → ports.scan_ports() on alive subdomains
                 → ReconRepository.upsert_port() for each
  3. tech        → tech.fingerprint_url() on alive subdomains
                 → ReconRepository.upsert_technology() for each
  4. urls        → crawler.crawl() on each alive subdomain
                 → ReconRepository.upsert_url() for each
  5. wayback     → wayback.fetch_wayback_urls()
                 → ReconRepository.upsert_url() for each
  6. js          → js_analyzer.analyze_page_js() on discovered pages
                 → ReconRepository.upsert_js_secret() for each
  Returns: summary dict {subdomains, alive, ports, techs, urls, js_secrets}
```

---

### `recon/subdomains.py`

**Purpose:** Passive and active subdomain enumeration.

**Flow:**
```
run_subdomain_enum(target_id, domain, passive_only)
  ├─ enumerate_passive(domain)
  │    ├─ crt.sh API  (certificate transparency)
  │    └─ HackerTarget API  (DNS brute-force results)
  │
  ├─ enumerate_active(domain)   [if not passive_only and subfinder available]
  │    └─ subprocess: subfinder -d <domain> -silent
  │
  └─ probe_alive(hostname)  [concurrent, semaphore=30]
       ├─ Try https://<hostname>  (8s timeout)
       └─ Try http://<hostname>
       → sets is_alive=True/False, status_code
```

Returns `list[Subdomain]`.

---

### `recon/ports.py`

**Purpose:** Port scanning via nmap.

**Flow:**
```
scan_ports(target_id, host, top_ports=1000)
  └─ subprocess: nmap -sV --top-ports <n> -oX - <host>
  └─ Parse XML output with xml.etree.ElementTree
  └─ Extract open ports → Port models with service/version
```

Requires nmap in PATH. Returns `list[Port]`.

---

### `recon/tech.py`

**Purpose:** HTTP-based technology fingerprinting without browser rendering.

**Signatures used:**

- `_SIGNATURES` — header-based (Server, X-Powered-By, X-Generator): Apache, Nginx, IIS, PHP, ASP.NET, Express, Django, Rails, Tomcat, Cloudflare, etc.
- `_BODY_SIGNATURES` — HTML body regex patterns: WordPress, Joomla, Drupal, React, Angular, Vue, jQuery, Bootstrap, etc.

**Flow:**
```
fingerprint_url(target_id, url)
  └─ httpx GET (10s timeout)
  └─ Match _SIGNATURES against response headers
  └─ Match _BODY_SIGNATURES against response body
  └─ Deduplicate by technology name
  Returns list[Technology] with confidence scores
```

---

### `recon/crawler.py`

**Purpose:** Async BFS web crawler to discover URLs and form parameters.

**Flow:**
```
crawl(target_id, seed_url, depth=3, scope_patterns, max_urls=500, concurrency=15)
  visited = set()
  queue = [(seed_url, 0)]
  semaphore = asyncio.Semaphore(concurrency)

  For each URL popped from queue:
    ├─ Skip if visited, depth exceeded, max_urls reached, extension in _SKIP_EXTENSIONS
    ├─ Skip if not in_scope(url, scope_patterns)
    ├─ httpx GET
    ├─ Extract href/src/action links via regex
    ├─ Parse query parameters
    ├─ Parse <form> inputs
    ├─ Capture interesting headers (Authorization, X-API-Key, Set-Cookie, etc.)
    ├─ Yield DiscoveredURL
    └─ Enqueue new links at depth+1
```

Returns `list[DiscoveredURL]`.

---

### `recon/js_analyzer.py`

**Purpose:** Download JavaScript files and extract secrets/endpoints using regex patterns.

**Secret patterns detected:**

| Pattern name | Example matches |
|---|---|
| `api_key` | Generic `api_key`, `apiKey`, `API_KEY` assignments |
| `aws_key` | `AKIA…` access key IDs |
| `google_api` | `AIza…` keys |
| `stripe_key` | `sk_live_…`, `pk_live_…` |
| `jwt` | `eyJ…` base64 tokens |
| `private_key` | `-----BEGIN RSA PRIVATE KEY-----` |
| `password` | `password =`, `passwd =` assignments |
| `token` | Generic token assignments |
| `endpoint` | `/api/v1/…` internal paths |
| `internal_url` | `https://internal.company.com/…` |
| `slack_webhook` | `hooks.slack.com/services/…` |
| `github_token` | `ghp_…` tokens |
| `mailchimp` | Mailchimp API keys |

**Flow:**
```
analyze_page_js(target_id, page_url)
  └─ httpx GET page
  └─ Regex extract all <script src="..."> and standalone .js URLs
  └─ analyze_js_file() for each (max 20 files)
       └─ httpx GET JS file
       └─ Run all _SECRET_PATTERNS against content
       └─ Yield JSSecret with confidence score
```

---

### `recon/wayback.py`

**Purpose:** Harvest historical URLs from the Wayback Machine CDX API.

**Flow:**
```
fetch_wayback_urls(target_id, domain, include_subdomains=True, limit=5000)
  └─ GET http://web.archive.org/cdx/search/cdx
        ?url=*.domain.com/*&output=json&limit=5000&filter=statuscode:200
  └─ Deduplicate by URL key
  └─ Filter: skip binary/media extensions (.jpg, .gif, .mp4, .woff, …)
  └─ Parse timestamp → datetime
  Returns list[DiscoveredURL] with source="wayback"
```

---

## Surface Mapping Module (`mewtwo/modules/surface/`)

### `surface/cli.py`

| Command | Description |
|---|---|
| `surface map [--ai]` | Run heuristics, optionally expand with AI |
| `surface show` | Display vectors with `--category` and `--risk` filters |
| `surface add` | Manually add a vector |
| `surface note <id> <text>` | Append note to vector description |

---

### `surface/mapper.py`

**Purpose:** Orchestrates heuristic + AI-based attack surface mapping.

**Flow:**
```
run_surface_map(target_id, db_path, use_ai)
  ├─ Load recon data: subdomains, techs, urls, js_secrets from ReconRepository
  ├─ heuristics.map_from_recon(...)  → list[AttackVector]
  ├─ if use_ai:
  │    AIClient.expand_attack_surface(recon_summary, existing_vectors)
  │    → additional list[AttackVector]
  └─ SurfaceRepository.upsert() each vector
```

---

### `surface/heuristics.py`

**Purpose:** Deterministic pattern-based vector identification from recon data.

**Four sub-checkers:**

**`_check_urls(urls)` — URL heuristics:**

| URL pattern | Category | Risk |
|---|---|---|
| HTTP 401/403 response | AUTHORIZATION | medium |
| `/login`, `/signin`, `/oauth`, `/saml` | AUTHENTICATION | high |
| `/admin`, `/dashboard`, `/control-panel` | AUTHORIZATION | high |
| File upload indicators (`upload`, `file=`, `attachment`) | INJECTION | high |
| `?redirect=`, `?return=`, `?next=`, `?url=` | CLIENT_SIDE (open redirect) | medium |
| `?id=`, `?user_id=`, `?account_id=` | AUTHORIZATION (IDOR) | high |
| `?url=`, `?uri=`, `?path=`, `?src=` | SSRF | high |
| `?search=`, `?query=`, `?q=`, `?filter=` | INJECTION (SQLi) | medium |
| Access-Control-Allow-Origin: * | CONFIGURATION (CORS) | low |

**`_check_technologies(techs)` — Tech stack heuristics:**

| Technology | Vector identified |
|---|---|
| WordPress | xmlrpc.php brute-force, REST API auth bypass, plugin vulnerabilities |
| Swagger UI | API documentation exposure, unauthenticated endpoints |
| GraphQL | Introspection enabled, DoS via deeply nested queries |
| Any site | Missing Content-Security-Policy header |

**`_check_js_secrets(js_secrets)` — Secret heuristics:**

| Secret type | Severity |
|---|---|
| api_key, aws_key, stripe_key, jwt, private_key | HIGH (exposed credentials) |
| endpoint | LOW (hidden attack surface) |

**`_check_subdomains(subdomains)` — Subdomain heuristics:**

Flags alive subdomains matching: `dev`, `staging`, `test`, `uat`, `admin`, `api`, `internal`, `vpn`, `remote`, `jira`, `jenkins`, `grafana`, `kibana`, `portal`, `manage` → AUTHORIZATION privilege escalation vector.

**Deduplication:** vectors with same (category, url) are merged.

---

## Hunt Module (`mewtwo/modules/hunt/`)

### `hunt/cli.py`

| Command | Options | Description |
|---|---|---|
| `hunt run` | `--category`, `--vector-id`, `--checks`, `--no-ai` | Execute checks against attack vectors |
| `hunt checks` | — | List all check names and descriptions |
| `hunt payload <vuln_class>` | `--url`, `--param` | Show or AI-generate payloads |
| `hunt ask <question>` | — | AI-assisted hunting question |

---

### `hunt/runner.py`

**Purpose:** Selects applicable vectors and dispatches checks concurrently.

**Flow:**
```
run_hunt(target_id, db_path, evidence_dir, category_filter, vector_id, check_names, use_ai)
  ├─ Load unchecked attack vectors (optionally filter by category or specific ID)
  ├─ For each vector:
  │    ├─ Determine applicable checks from vector.category
  │    ├─ Filter by check_names if specified
  │    └─ async run all checks concurrently via httpx.AsyncClient (timeout=15s)
  │         For each FindingDraft returned:
  │           ├─ if use_ai: AIClient.triage_finding() → is_finding, severity, confidence
  │           ├─ save_evidence() → writes raw HTTP to disk
  │           ├─ FindingRepository.upsert(Finding(status=DRAFT))
  │           └─ Print result to console
  └─ SurfaceRepository.mark_checked(vector_id)
```

---

### `hunt/checks/base.py`

Abstract base for all vulnerability checks:

```
FindingDraft
  title, vuln_class, severity, url, parameter
  description, evidence: list[str]
  references: list[str]
  raw_request: str | None
  raw_response: str | None

BaseCheck (abstract)
  name: str
  description: str
  vuln_class: str
  references: list[str]
  applicable_categories: list[VectorCategory]

  async run(vector: AttackVector, client: httpx.AsyncClient, ai: AIClient)
    → list[FindingDraft]   (abstract)

  _evidence_snippet(request, response) → str
```

---

### `hunt/checks/__init__.py`

Exports `ALL_CHECKS` list containing every check class instance: `IDORCheck, XSSCheck, SQLiCheck, SSRFCheck, AuthCheck, OpenRedirectCheck, CORSCheck, InfoDisclosureCheck, RateLimitCheck, PathTraversalCheck, XXECheck`.

---

### `hunt/checks/auth.py` — AuthCheck

**Applicable:** AUTHENTICATION

**Tests:**
1. **Brute force protection:** Sends 5 failed login attempts. If no 429/rate-limit header seen → missing brute force protection (MEDIUM).
2. **JWT alg:none:** Decodes JWT from response, rewrites header to `{"alg":"none"}`, removes signature, resends. If 200 → algorithm confusion (HIGH).

---

### `hunt/checks/idor.py` — IDORCheck

**Applicable:** AUTHORIZATION

**Tests:** Finds parameters named `id`, `user_id`, `uid`, `account_id`, `record_id`, `object_id`, `item_id`. Substitutes probes: `1`, `2`, `0`, `999999`, `admin`, `../1`. If any returns HTTP 200 with body > 100 bytes → IDOR candidate (HIGH). Optionally AI-triaged.

---

### `hunt/checks/xss.py` — XSSCheck

**Applicable:** CLIENT_SIDE, INJECTION

**Payloads (7 default):** `<script>alert(1)</script>`, `"><script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `'"><img src=x onerror=alert(1)>`, `javascript:alert(1)`, `<svg onload=alert(1)>`, `"><svg onload=alert(1)>`. More loaded from `payloads/xss.txt` if present.

**Method:** Injects payload into first 5 query parameters (GET request). Checks if raw payload appears unencoded in response body → reflected XSS candidate (MEDIUM). Captures full raw request/response as evidence.

---

### `hunt/checks/sqli.py` — SQLiCheck

**Applicable:** INJECTION

**Tests:**
1. **Error-based:** Injects `'`, `"`, `' OR 1=1--`, `" OR 1=1--`, `'; DROP TABLE users--`. Looks for SQL error patterns in response (mysql error, syntax error, ORA-, pg_query, etc.).
2. **Boolean-blind:** Sends true condition (`' OR '1'='1`) vs false condition (`' OR '1'='2`). If response length difference > 200 bytes → blind SQLi candidate (HIGH).

Tests first 5 parameters per vector.

---

### `hunt/checks/ssrf.py` — SSRFCheck

**Applicable:** SSRF

**Payloads (6):** `http://169.254.169.254/latest/meta-data/` (AWS IMDS), `http://metadata.google.internal/computeMetadata/v1/` (GCP), `http://169.254.169.254/metadata/instance` (Azure), `http://100.100.100.200/latest/meta-data/` (Alibaba), `http://localhost/`, `file:///etc/passwd`, `dict://localhost:6379/`.

**Detection:** Checks for AWS metadata response patterns (`ami-id`, `instance-id`) or internal service indicators in response body.

---

### `hunt/checks/cors.py` — CORSCheck

**Applicable:** CONFIGURATION, AUTHORIZATION

**Tests 3 origins:**
1. `https://evil.com` → arbitrary origin
2. `null` → null origin (sandboxed iframe bypass)
3. Reflected origin (send `Origin: https://attacker.target.com`)

**Severity logic:**
- `ACAO: *` + `ACAC: true` → CRITICAL (credentialed wildcard)
- `ACAO: null` + `ACAC: true` → HIGH
- Reflected origin + `ACAC: true` → HIGH
- `ACAO: *` alone → LOW

---

### `hunt/checks/open_redirect.py` — OpenRedirectCheck

**Applicable:** CLIENT_SIDE

**Payloads (8):** `https://evil.com`, `//evil.com`, `/\evil.com`, `https:`, `///evil.com`, `\x00https://evil.com`, `%0d%0ahttps://evil.com`, `javascript:alert(1)`.

**Method:** Sends without following redirects. Checks for 3xx response with `evil.com` in `Location` header → open redirect (MEDIUM).

---

### `hunt/checks/info_disclosure.py` — InfoDisclosureCheck

**Applicable:** INFO_DISCLOSURE, CONFIGURATION, AUTHENTICATION, AUTHORIZATION

**Probes 32 sensitive paths including:** `.env`, `.git/config`, `config.php`, `/actuator/env`, `/phpinfo.php`, `/swagger.json`, `/api-docs`, `/robots.txt`, `/sitemap.xml`, `/server-status`, `/.DS_Store`, `/backup.sql`, `/dump.sql`, `/wp-config.php`, `/.htpasswd`, `/web.config`, `/crossdomain.xml`, `/security.txt`, `/.well-known/security.txt`, `/graphql` (introspection), `/console` (Spring/Rails), etc.

**Severity:** CRITICAL for `.env` with secrets; HIGH for `.env`, `.git/config`, `/actuator`; MEDIUM for phpinfo, stack traces; LOW for API docs.

Also detects stack traces in any response via regex (traceback, exception, at line \d+, etc.).

---

### `hunt/checks/rate_limit.py` — RateLimitCheck

**Applicable:** AUTHENTICATION, AUTHORIZATION, CONFIGURATION

**Method:** Targets login-related paths (`/login`, `/signin`, `/otp`, `/reset-password`, `/2fa`). Sends 15 rapid requests. If ≥10 succeed (2xx/3xx, no 429/503/locked) → missing rate limiting (MEDIUM).

---

### `hunt/checks/path_traversal.py` — PathTraversalCheck

**Applicable:** INJECTION, CONFIGURATION, INFO_DISCLOSURE

**Parameters targeted:** `file`, `path`, `page`, `doc`, `template`, `view`, `image`, `filename`, `include`, `load`, `read`.

**Payloads (10):** `../../../etc/passwd`, URL-encoded variants (`%2e%2e%2f`), double-encoded (`%252e%252e%252f`), Windows (`..\..\windows\win.ini`), null byte (`../../../etc/passwd%00`).

**Detection:** `/etc/passwd` → checks for `root:` pattern; Windows → checks for `[extensions]` from win.ini.

---

### `hunt/checks/xxe.py` — XXECheck

**Applicable:** INJECTION, CONFIGURATION

**Tests only XML endpoints** (Content-Type contains `xml`).

**3 payload types:**
1. File read: `SYSTEM "file:///etc/passwd"` → detect `root:` in response
2. Error-based: `SYSTEM "file:///nonexistent_xxe_probe"` → detect error mentioning path
3. SSRF: `SYSTEM "http://169.254.169.254/..."` → detect AWS metadata in response

---

### `hunt/payloads/`

Static payload lists loaded by checks:
- `xss.txt` — XSS payload strings (one per line)
- `sqli.txt` — SQL injection strings
- `ssrf.txt` — SSRF probe URLs

---

## Findings Module (`mewtwo/modules/findings/`)

### `findings/cli.py`

| Command | Description |
|---|---|
| `findings add` | Interactive prompt: title, url, vuln_class, severity, description, parameter |
| `findings list` | Table with filters `--severity`, `--status`, `--vuln-class` |
| `findings show <id>` | Full detail panel with markdown rendering |
| `findings status <id> <state>` | Transition status: draft→confirmed→reported→accepted/duplicate/closed |
| `findings cvss <id>` | Interactive CVSS 3.1 calculator |
| `findings enrich <id>` | AI drafts description, impact, steps, remediation |
| `findings attach <id> <file>` | Attach screenshot, PoC, Burp export |
| `findings evidence <id>` | Show HTTP captures and attachments |
| `findings delete <id>` | Remove finding |

---

### `findings/cvss.py`

**Purpose:** CVSS 3.1 base score calculation and interactive CLI input.

```
calculate_cvss(vector: CVSSVector) → float
  Metrics and weights per CVSS 3.1 spec:
    AV:  N=0.85  A=0.62  L=0.55  P=0.20
    AC:  L=0.77  H=0.44
    PR:  N=0.85  L=0.62/0.50  H=0.27/0.50  (scope-dependent)
    UI:  N=0.85  R=0.62
    S:   U/C (affects PR weighting)
    C/I/A: N=0.00  L=0.22  H=0.56

score_to_severity(score) → Severity
  ≥9.0 → CRITICAL
  ≥7.0 → HIGH
  ≥4.0 → MEDIUM
  >0.0 → LOW
  else → INFORMATIONAL

interactive_cvss() → CVSSVector
  Click prompts for all 8 metrics via menu choices
```

---

## Report Module (`mewtwo/modules/report/`)

### `report/cli.py`

| Command | Options | Description |
|---|---|---|
| `report generate` | `--format md\|html\|pdf\|all`, `--output`, `--include draft\|confirmed\|all`, `--no-ai` | Build full report |
| `report pdf` | `--output` | PDF only (requires weasyprint) |
| `report preview` | — | Terminal markdown preview |
| `report export <id>` | `--format` | Single finding standalone report |
| `report submit <id>` | H1/Bugcrowd credentials, `--dry-run` | Submit to platform API |

---

### `report/builder.py`

**Purpose:** Assembles the report context dict consumed by templates.

**Flow:**
```
build_report_context(db_path, include_statuses, use_ai)
  ├─ Load target metadata
  ├─ FindingRepository.for_target() filtered by include_statuses
  ├─ Sort by severity (critical first)
  ├─ if use_ai:
  │    For each finding: AIClient.enrich_finding() → updates description/impact/steps
  │    AIClient.write_executive_summary(target, findings) → 200–350 word summary
  └─ Return context dict:
       {target, findings, executive_summary, report_date, finding_counts_by_severity}
```

---

### `report/renderer.py`

**Purpose:** Jinja2-based format rendering.

```
render_markdown(context) → str
  └─ Loads report.md.j2, renders with context

render_html(context) → str
  └─ Loads report.html.j2, renders with context
  └─ Includes embedded CSS with severity colour coding

render_pdf(context, output_path)
  └─ render_html() first
  └─ weasyprint.HTML(string=html).write_pdf(output_path)
  └─ Requires: libpango, libglib2.0 system libraries
```

---

### `report/templates/report.md.j2`

Jinja2 markdown template. Structure:
```
# Bug Bounty Report — {target.name}
## Executive Summary
{executive_summary}
## Findings Summary Table
| Title | Severity | Status | CVSS |
## Critical Findings
### {finding.title}
**Severity:** / **URL:** / **Parameter:** / **CVSS:**
#### Description / Impact / Steps to Reproduce / Remediation / References
## High Findings  (repeat per severity)
…
```

---

### `report/templates/report.html.j2`

HTML version with embedded CSS. Same structure as markdown template but with:
- Severity-colored badge spans (red/orange/yellow/blue/grey)
- Print-friendly CSS with page breaks between findings
- Responsive table layout for the findings summary

---

### `report/submit.py`

**Purpose:** Submits findings directly to HackerOne or Bugcrowd APIs.

**HackerOneClient:**
```
POST https://api.hackerone.com/v1/reports
  Auth: HTTP Basic (username:api_token)
  Body: {title, vulnerability_information, severity.rating, weakness_id, structured_scope.asset_identifier}
  → Returns report ID and URL (https://hackerone.com/reports/<id>)
```

**BugcrowdClient:**
```
POST https://api.bugcrowd.com/v4/submissions
  Auth: Bearer token header
  Body: {title, description, vrt_id, severity, target_url, program_code}
  severity mapping: critical→1, high→2, medium→3, low→4, informational→5
  vrt_id: _vuln_class_to_vrt() maps vuln_class strings to Bugcrowd VRT taxonomy IDs
```

---

## AI Module (`mewtwo/modules/ai/`)

### `ai/cli.py`

| Command | Options | Description |
|---|---|---|
| `ai ask <question>` | `--context recon\|surface\|findings\|all`, `--no-stream` | One-shot Q&A |
| `ai chat` | — | Interactive multi-turn conversation |
| `ai analyze` | `--phase` | Full workspace analysis with insights |
| `ai chains` | `--severity` | Identify attack chains linking findings |
| `ai payloads <vuln_class>` | `--url`, `--param` | Context-aware payload generation |

---

### `ai/client.py`

**Purpose:** Anthropic SDK wrapper providing high-level task methods used throughout the toolkit.

**Core completion methods:**
```
complete(system, messages, tools, max_tokens)
  → str (text) or dict (tool_use.input)

stream(system, messages, max_tokens)
  → AsyncGenerator[str]   (text deltas for live display)

complete_with_tool(system, messages, tool, max_tokens)
  → dict   (tool input, forces tool_choice={"type":"tool"})
```

**Workspace context injection:**
```
workspace_context_snippet(db_path) → str
  Returns compact JSON:
  {target_name, platform, subdomains, alive_subdomains, urls, attack_vectors, findings}
```

**High-level task methods:**

| Method | Uses | Returns |
|---|---|---|
| `analyze_recon(subdomains, techs, js_secrets, db_path)` | `ATTACK_VECTORS_TOOL` | `list[AttackVector]` |
| `expand_attack_surface(recon_summary, existing_vectors, db_path)` | `ATTACK_VECTORS_TOOL` | `list[AttackVector]` |
| `triage_finding(check_name, vector_url, evidence, db_path)` | `TRIAGE_TOOL` | `{is_finding, severity, confidence, reason}` |
| `generate_payloads(vuln_class, url, param, tech_stack)` | text completion | `list[str]` |
| `enrich_finding(finding_dict, db_path)` | `ENRICHMENT_TOOL` | `{description, impact, steps, remediation, references}` |
| `write_executive_summary(target_name, findings)` | text completion | `str` (200–350 words) |
| `analyze_attack_chains(findings, db_path)` | `ATTACK_CHAIN_TOOL` | `list[chain dicts]` |
| `generate_personalised_payloads(vuln_class, url, param, tech_stack, existing)` | `PERSONALISED_PAYLOAD_TOOL` | `list[{payload, technique, rationale, placement}]` |
| `ask(question, context, stream)` | text/stream | `str` or `AsyncGenerator[str]` |

---

### `ai/prompts.py`

**Purpose:** All system and user prompt templates. Centralised here so no f-strings appear at call sites.

**Personas:** `_PURPLE_TEAM_PERSONA` — senior offensive/defensive security engineer persona emphasising low false positives.

**System prompts:**

| Function | Persona focus |
|---|---|
| `recon_analysis_system()` | Identify high-value attack surface from recon data |
| `surface_expansion_system()` | Chained vulnerabilities, business logic flaws |
| `triage_system()` | Assess real vulnerability vs false positive |
| `payload_system()` | Generate 5–8 payloads for specific vuln class |
| `enrichment_system()` | Write professional bug bounty report sections |
| `exec_summary_system()` | Executive summary for leadership audience |
| `attack_chain_system()` | Link multiple findings into attack narratives |
| `personalised_payload_system()` | Highly targeted payloads for specific tech stack |
| `ask_system()` | General-purpose bug bounty research assistant |

Each system prompt has a paired `*_user()` function that formats the data payload for the user message turn.

---

### `ai/tools.py`

Claude tool (function call) schema definitions for structured output:

| Tool constant | Input fields | Purpose |
|---|---|---|
| `ATTACK_VECTORS_TOOL` | vectors: `[{category, title, description, url, parameters, risk_rating, rationale}]` | Surface mapping output |
| `TRIAGE_TOOL` | `{is_finding, severity, vuln_class, title, impact, confidence, follow_up, reason}` | Hunt triage decision |
| `ENRICHMENT_TOOL` | `{description, impact, reproduction_steps, remediation, references, suggested_severity}` | Finding enrichment |
| `ATTACK_CHAIN_TOOL` | chains: `[{title, combined_severity, finding_ids, attack_narrative, business_impact, prerequisites, remediation_priority}]` | Chain analysis |
| `PERSONALISED_PAYLOAD_TOOL` | payloads: `[{payload, technique, rationale, placement}]` | Targeted payloads |
| `CVSS_TOOL` | `{attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability, rationale}` | CVSS suggestion |

---

## Workspace I/O (`mewtwo/workspace_io.py`)

**Purpose:** Archive and restore workspaces for portability across machines or for sharing.

**Export flow:**
```
export_workspace(ws: Path, output: Path | None) → Path
  ├─ Determine output path (default: ./<slug>-<date>.mewtwo)
  ├─ Build tar.gz with:
  │    mewtwo-export/manifest.json   ← version, slug, exported_at, file list
  │    mewtwo-export/mewtwo.db       ← SQLite database
  │    mewtwo-export/reports/        ← generated report files
  │    mewtwo-export/evidence/       ← HTTP captures, attachments
  └─ Return archive Path
```

**Import flow:**
```
import_workspace(archive: Path, workspaces_dir: Path, activate: bool) → str
  ├─ Open tar.gz, read manifest.json
  ├─ Raise FileExistsError if slug already exists in workspaces_dir
  ├─ Extract db, reports/, evidence/ to new workspace directory
  ├─ if activate: config.set_active_workspace(slug)
  └─ Return slug
```

---

## TUI Dashboard (`mewtwo/tui.py`)

**Purpose:** Optional Textual-based interactive terminal dashboard (requires `pip install mewtwo[tui]`).

**Widgets:**
- `StatCard` — Label + value display with configurable colour

**MewtwoApp tabs:**

| Tab | Content |
|---|---|
| Overview | 6 StatCards (subdomains, alive, URLs, vectors, findings, critical) + Recent Findings DataTable |
| Recon | Subdomains DataTable (hostname, alive, status, IPs) |
| Attack Surface | Vectors DataTable (category, title, URL, risk, checked) |
| Hunt | All Findings DataTable (title, severity, status, URL) |

**Keybindings:** `r` refresh data, `q` quit.

**Data source:** Reads directly from active workspace SQLite DB on load and refresh.

---

## Docs (`docs/`)

Nine reference guides — not generated, hand-written design documentation:

| File | Topic |
|---|---|
| `01-architecture.md` | System design, module boundaries, data flow |
| `02-workspace.md` | Workspace lifecycle, init, scope management |
| `03-recon.md` | Recon module details, passive vs active, tool dependencies |
| `04-surface.md` | Surface mapping heuristics and AI expansion |
| `05-hunt.md` | Hunt module, check list, evidence capture |
| `06-findings.md` | Finding lifecycle, CVSS, enrichment |
| `07-ai.md` | AI integration, Claude tools, prompt engineering |
| `08-report.md` | Report generation, formats, platform submission |
| `09-tui-workspace.md` | TUI dashboard usage and configuration |

---

## External Tool Dependencies

| Tool | Used by | Fallback |
|---|---|---|
| `nmap` | `recon/ports.py` | Skipped if not in PATH |
| `subfinder` | `recon/subdomains.py` | Passive-only mode |
| `weasyprint` | `report/renderer.py` | PDF unavailable |
| `textual` | `tui.py` | TUI unavailable |

---

## Data Flow Diagram

```
                         ┌──────────────┐
                         │  mewtwo CLI  │
                         └──────┬───────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
       ┌─────────────┐  ┌────────────────┐  ┌──────────────┐
       │    config   │  │      db        │  │ workspace_io │
       │  (paths,env)│  │ (schema init)  │  │ (export/imp) │
       └─────────────┘  └────────────────┘  └──────────────┘
                                │
                    ┌───────────┴──────────────┐
                    │        SQLite DB         │
                    └───────────┬──────────────┘
                                │  (read/write via storage/)
         ┌──────────────────────┼───────────────────────┐
         ▼                      ▼                       ▼
  ┌─────────────┐      ┌──────────────────┐    ┌──────────────────┐
  │    recon    │─────▶│     surface      │───▶│      hunt        │
  │  subdomains │      │  attack vectors  │    │  vuln checks     │
  │  ports      │      │  heuristics      │    │  XSS/SQLi/IDOR.. │
  │  tech       │      │  AI expansion    │    │  AI triage       │
  │  crawler    │      └──────────────────┘    └────────┬─────────┘
  │  wayback    │                                       │
  │  js_analyze │                               ┌───────▼──────────┐
  └─────────────┘                               │    findings      │
                                                │  CVSS scoring    │
                                                │  AI enrichment   │
                                                └───────┬──────────┘
                                                        │
                                                ┌───────▼──────────┐
                                                │     report       │
                                                │  MD / HTML / PDF │
                                                │  H1 / Bugcrowd   │
                                                └──────────────────┘
                                                        │
                                               ┌────────▼─────────┐
                                               │   AI module      │
                                               │ (cross-cutting)  │
                                               │ Claude API calls │
                                               └──────────────────┘
```

---

## Key Design Patterns

| Pattern | Where | Why |
|---|---|---|
| Repository pattern | `storage/` | Decouples business logic from sqlite-utils API |
| Pydantic v2 models | `models/` | Type-safe data with automatic validation |
| Click command groups | All `*/cli.py` | Composable hierarchical CLI structure |
| Async/await + httpx | All network I/O | Concurrent requests without threading |
| Claude tool use | `ai/client.py`, `ai/tools.py` | Reliable structured JSON output from LLM |
| Streaming responses | `ai/client.py` | Real-time markdown rendering in terminal |
| Active workspace symlink | `config.py` | Single global pointer; `use` command swaps it |
| Idempotent upserts | `storage/` | Safe to re-run any phase without duplicates |
| Evidence capture | `utils/evidence.py` + `hunt/runner.py` | Raw HTTP proof stored alongside findings |
