# Mewtwo — Workspace, Config & Database

## config.py

This file is the single source of truth for all filesystem paths. Every other module
imports from here instead of building paths manually.

```python
def mewtwo_home() -> Path:
    home = Path(os.environ.get("MEWTWO_HOME", Path.home() / ".mewtwo"))
    home.mkdir(parents=True, exist_ok=True)
    return home
```
Reads `MEWTWO_HOME` from the environment — useful if you want workspaces on an
external drive or a non-standard location. Falls back to `~/.mewtwo`.

```python
def active_workspace() -> Path | None:
    link = current_symlink()          # ~/.mewtwo/current
    if link.exists() or link.is_symlink():
        target = link.resolve()       # follow the symlink
        if target.exists():
            return target
    return None
```
Uses `is_symlink()` rather than just `exists()` because a broken symlink (pointing to
a deleted workspace) returns `False` for `exists()` but `True` for `is_symlink()`.
This guards against a stale link crashing things.

```python
def set_active_workspace(slug: str) -> Path:
    ws = workspace_path(slug)
    if not ws.exists():
        raise FileNotFoundError(...)
    link = current_symlink()
    if link.is_symlink():
        link.unlink()        # remove old symlink first
    link.symlink_to(ws)      # point to new workspace
    return ws
```
Why a symlink? Because it makes `active_workspace()` a single `readlink` call with no
config file to parse or update. Switching workspaces is atomic.

---

## db.py

Defines the SQLite schema using `sqlite-utils`. The `get_db()` function opens the
database and ensures all tables exist.

```python
def _ensure_schema(db: Database) -> None:
    if "targets" not in db.table_names():
        db["targets"].create({
            "id": str, "name": str, "slug": str,
            "platform": str, "program_url": str,
        }, pk="id")
```
`sqlite-utils` creates tables from plain Python dicts — the key is the column name,
the value is the Python type (which maps to a SQLite type). This is more readable than
raw `CREATE TABLE` SQL.

Tables created:

| Table | Purpose |
|-------|---------|
| `targets` | One row per workspace — name, slug, platform, program URL |
| `scope` | In-scope / out-of-scope patterns for the target |
| `sessions` | Metadata for each recon run |
| `subdomains` | Every discovered subdomain + liveness status |
| `ports` | Open ports per host |
| `technologies` | Fingerprinted tech stack per host |
| `urls` | Every URL discovered by crawler or Wayback Machine |
| `js_secrets` | Secrets/endpoints extracted from JavaScript files |
| `attack_vectors` | Mapped attack surface — one row per testable vector |
| `findings` | Confirmed/draft vulnerability findings |

---

## models/ — Pydantic Data Models

### Why Pydantic?

Pydantic validates data at creation time. If you try to create a `Finding` with
`severity="oops"`, it raises a `ValidationError` immediately — rather than silently
storing garbage in the database.

### models/finding.py

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    ...
```
Using `str, Enum` means the value serialises as the string `"critical"` rather than
`Severity.CRITICAL` — SQLite stores the string directly.

```python
class CVSSVector(BaseModel):
    attack_vector: str = "N"
    attack_complexity: str = "L"
    ...
    score: float = 0.0
    vector_string: str = ""
```
All CVSS metric fields default to the "most severe" value so a partially-filled
CVSSVector doesn't silently produce a misleadingly low score.

```python
class Evidence(BaseModel):
    kind: str       # "request" | "response" | "screenshot" | "note"
    content: str    # raw content OR a file path for file attachments
    caption: str = ""
```
Evidence is intentionally simple — just a kind tag and a content string. File
attachments store the path in `content`; inline notes store the text.

### models/surface.py

```python
class VectorCategory(str, Enum):
    AUTHENTICATION   = "authentication"
    AUTHORIZATION    = "authorization"
    INJECTION        = "injection"
    SSRF             = "ssrf"
    INFO_DISCLOSURE  = "info_disclosure"
    BUSINESS_LOGIC   = "business_logic"
    CLIENT_SIDE      = "client_side"
    CONFIGURATION    = "configuration"
```
These eight categories map directly to the `applicable_categories` list on every hunt
check. When the runner dispatches checks, it filters by whether the vector's category
is in the check's list — avoiding running an XSS check against a configuration vector.

---

## storage/ — Repository Pattern

### storage/base.py

```python
class BaseRepository:
    def __init__(self, db: Database):
        self.db = db

    def get(self, id: str) -> dict | None:
        try:
            return dict(self.db[self.table_name].get(id))
        except Exception:
            return None
```

All repositories inherit from `BaseRepository`. The `_ser` helper converts Python
types to SQLite-safe values:

```python
def _ser(value) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    if isinstance(value, Enum):
        return value.value
    return value
```
SQLite doesn't understand Python `datetime` or `list` objects. `_ser` converts them
to strings/JSON before writing.

`_row_to_dict` does the reverse — it looks at field names ending in `_json` and
parses them back to Python objects:

```python
def _deserialize_row(self, row: dict) -> dict:
    for key in self.json_fields:
        if key in row and row[key]:
            row[key.removesuffix("_json")] = json.loads(row[key])
    for key in self.bool_fields:
        if key in row:
            row[key] = bool(row[key])   # SQLite stores bools as 0/1
    return row
```

### Why upsert instead of insert?

Every repository uses `db["table"].upsert(..., pk="id")` rather than `insert`. This
means re-running recon doesn't create duplicate rows — it updates existing ones in
place. The `id` field acts as the idempotency key.

---

## cli.py — Root Command Group

```python
@click.group()
@click.version_option(__version__, prog_name="mewtwo")
def cli():
    """Mewtwo — AI-assisted bug bounty toolkit."""
```
`@click.group()` creates a command group. All sub-commands (`init`, `use`, `recon`,
etc.) are attached to this group.

```python
@cli.command("init")
@click.argument("name")
@click.option("--platform", default="")
def init_cmd(name, platform, ...):
    slug = slugify(name)          # "My Target" → "my-target"
    ws = config.workspace_path(slug)

    if ws.exists():               # already exists — just switch to it
        config.set_active_workspace(slug)
        return

    ws.mkdir(parents=True)
    (ws / "reports").mkdir()
    (ws / "evidence").mkdir()

    db = get_db(config.db_path(ws))
    repo = TargetRepository(db)
    repo.upsert(target)
    config.set_active_workspace(slug)
```
`init` creates the directory tree, initialises the DB schema, writes the `Target`
row, and sets the symlink — all in one command. Subsequent `init` calls for the same
slug just switch to the existing workspace.

The `export` and `import` commands at the bottom of `cli.py` delegate entirely to
`workspace_io.py` to keep the CLI thin.
