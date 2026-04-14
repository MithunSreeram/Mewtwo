# Mewtwo — Architecture Overview

## Project Layout

```
mewtwo/
├── cli.py                  # Root CLI entry point — all commands registered here
├── config.py               # Path resolution, active workspace, env vars
├── db.py                   # SQLite schema definition
├── tui.py                  # Textual TUI dashboard
├── workspace_io.py         # Workspace export/import (.mewtwo archives)
│
├── models/                 # Pydantic data models (pure data, no DB logic)
│   ├── target.py           # Target, ScopeEntry, ScopeType
│   ├── recon.py            # Subdomain, Port, Technology, DiscoveredURL, JSSecret
│   ├── surface.py          # AttackVector, VectorCategory
│   ├── finding.py          # Finding, Severity, FindingStatus, Evidence, CVSSVector
│   └── session.py          # Session (recon run metadata)
│
├── storage/                # Repository pattern — DB read/write per model
│   ├── base.py             # BaseRepository with shared helpers
│   ├── targets.py          # TargetRepository, ScopeRepository
│   ├── recon.py            # ReconRepository (subdomains, ports, tech, urls, js)
│   ├── surface.py          # SurfaceRepository (attack vectors)
│   ├── findings.py         # FindingRepository
│   └── sessions.py         # SessionRepository
│
├── utils/
│   ├── console.py          # Rich helpers: info/warn/error/success/severity_style
│   ├── http.py             # Shared httpx client factory
│   ├── process.py          # Async subprocess runner (nmap, subfinder)
│   ├── validators.py       # slugify, in_scope pattern matching
│   └── evidence.py         # HTTP request/response capture to disk
│
└── modules/
    ├── recon/              # Subdomain enum, ports, tech fingerprint, crawl, wayback, JS
    ├── surface/            # Heuristic attack surface mapper
    ├── hunt/               # Vulnerability checks + runner
    ├── findings/           # CVSS calculator, findings CLI
    ├── report/             # Report builder, renderer, PDF, platform submission
    └── ai/                 # Anthropic SDK client, prompts, tool schemas
```

---

## Data Flow

```
recon run
    └─► subdomains, ports, technologies, urls, js_secrets  →  SQLite

surface map
    └─► reads recon tables → heuristics → attack_vectors  →  SQLite

hunt run
    └─► reads attack_vectors → checks → findings          →  SQLite
                                                               evidence/

report generate
    └─► reads findings → builder → Jinja2 → .md / .html / .pdf
                       └─► AI enrichment (optional)
                       └─► platform submission (optional)
```

---

## Design Principles

### 1. Models are decoupled from storage

`mewtwo/models/` contains only Pydantic classes — pure data with validation.
`mewtwo/storage/` contains repository classes that handle all DB operations.

This means you can create a `Finding` object, pass it around, validate it, and only
call `repo.upsert(finding)` when you actually want it persisted. The model never
touches the database itself.

### 2. All async I/O uses httpx + asyncio

Every module that makes network requests uses `httpx.AsyncClient` with
`asyncio.Semaphore` for concurrency control. This keeps recon fast without
flooding the target.

### 3. AI uses forced tool-use for structured output

Instead of asking Claude to "return JSON", Mewtwo uses the Anthropic tool-use API
with `tool_choice={"type": "tool", "name": "..."}`. This forces a schema-validated
response every time — no JSON parsing failures.

### 4. Workspaces are filesystem-first

Each workspace is a directory at `~/.mewtwo/workspaces/<slug>/`. The active workspace
is tracked by a symlink at `~/.mewtwo/current`. No global config file is needed —
switching workspaces is just relinking the symlink.

### 5. Graceful optional dependencies

Heavy optional deps (weasyprint for PDF, textual for TUI) are guarded with
`try/except ImportError` everywhere and point to `pip install 'mewtwo[pdf|tui]'`.
The core toolkit works without them.
