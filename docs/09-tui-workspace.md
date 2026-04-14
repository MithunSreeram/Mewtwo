# Mewtwo — TUI Dashboard & Workspace I/O

---

## tui.py — Textual Dashboard

The TUI is a single-file Textual app. It's guarded with a try/except so the whole
codebase works without `textual` installed:

```python
def launch_dashboard() -> None:
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Header, Footer, Static, DataTable, ...
    except ImportError:
        raise ImportError("pip install 'mewtwo[tui]'")
```

The App class and all its widget classes are defined inside `launch_dashboard()`.
This is unusual but necessary — if the Textual classes were defined at module level,
importing `tui.py` would crash on a machine without `textual`.

### StatCard widget

```python
class StatCard(Static):
    def __init__(self, label: str, value: str, color: str = "cyan", **kwargs):
        super().__init__(**kwargs)
        self._label = label
        self._value = value
        self._color = color

    def render(self):
        return (
            f"[bold {self._color}]{self._value}[/bold {self._color}]\n"
            f"[dim]{self._label}[/dim]"
        )
```

`Static` is a Textual widget that displays Rich markup. Overriding `render()` returns
the markup string — the big number on top, the label below. When data loads,
`_value` is updated and `w.refresh()` is called to redraw.

### Layout — TabbedContent + compose

```python
def compose(self) -> ComposeResult:
    yield Header()
    with TabbedContent():
        with TabPane("Overview", id="overview"):
            yield Container(
                Horizontal(
                    StatCard("Subdomains", "—", "cyan", id="stat_subs"),
                    StatCard("Alive Hosts", "—", "green", id="stat_alive"),
                    StatCard("URLs", "—", "blue", id="stat_urls"),
                    StatCard("Vectors", "—", "yellow", id="stat_vectors"),
                    StatCard("Findings", "—", "red", id="stat_findings"),
                    classes="stat-row",
                )
            )
            yield Label("Recent Findings", classes="section-title")
            yield DataTable(id="findings_table")

        with TabPane("Recon", id="recon"):
            yield DataTable(id="subs_table")
        with TabPane("Attack Surface", id="surface"):
            yield DataTable(id="vectors_table")
        with TabPane("Hunt", id="hunt"):
            yield DataTable(id="all_findings_table")
    yield Footer()
```

`compose()` is a generator — `yield` adds widgets to the DOM. `TabbedContent`
manages the tab switching. `DataTable` is Textual's scrollable grid widget.

### CSS — defined inline

```python
CSS = """
Screen {
    background: #0d1117;   /* GitHub dark background */
}
StatCard {
    background: #161b22;
    border: tall #30363d;  /* tall = double border */
    min-width: 18;
    height: 5;
    content-align: center middle;
}
DataTable {
    background: #0d1117;
    border: tall #30363d;
}
"""
```

Textual uses its own CSS subset — not full web CSS. `border: tall` means a
double-line box. `content-align: center middle` centers the stat card text both
horizontally and vertically.

### Data loading

```python
def _load_data(self) -> None:
    db = get_db(self._db_path)
    tid = targets[0]["id"]

    # Count queries
    subs_total = db["subdomains"].count_where("target_id = ?", [tid])
    subs_alive = db["subdomains"].count_where("target_id = ? AND is_alive = 1", [tid])
    urls       = db["urls"].count_where("target_id = ?", [tid])
    vectors    = db["attack_vectors"].count_where("target_id = ?", [tid])
    findings   = db["findings"].count_where("target_id = ?", [tid])

    # Update StatCards
    self.query_one("#stat_subs", StatCard)._value = str(subs_total)
    ...
    for w in self.query("StatCard"):
        w.refresh()
```

`query_one("#stat_subs", StatCard)` finds the widget with CSS ID `stat_subs`.
`_value` is updated directly (not reactive), so `w.refresh()` is needed to trigger
a re-render. `self.query("StatCard")` returns all StatCard instances, so one loop
refreshes all five.

### Severity styling

```python
sev_styled = {
    "critical": f"[bold red]{sev}[/bold red]",
    "high":     f"[yellow]{sev}[/yellow]",
    "medium":   f"[blue]{sev}[/blue]",
    "low":      f"[dim]{sev}[/dim]",
}.get(sev, sev)
ft.add_row(sev_styled, row.get("title")[:55], ...)
```

Rich markup is allowed directly in `DataTable.add_row()` arguments — Textual
renders it with colour. Column widths are auto-sized.

### Keybindings

```python
BINDINGS = [
    ("r", "refresh", "Refresh"),
    ("q", "quit",    "Quit"),
]

def action_refresh(self) -> None:
    self._load_data()
    self.notify("Dashboard refreshed", timeout=2)
```

`BINDINGS` maps keys to action names. Textual automatically looks for a method
named `action_<name>` and calls it. `self.notify()` shows a toast notification
in the bottom-right corner for 2 seconds.

---

## workspace_io.py — Export / Import

### Export: tarfile + manifest

```python
def export_workspace(ws: Path, output: Path | None = None) -> Path:
    slug = ws.name
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    archive_name = f"{slug}_{timestamp}.mewtwo"
    dest = output or (ws.parent.parent / "exports" / archive_name)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp) / "mewtwo-export"
        tmp_root.mkdir()

        shutil.copy2(ws / "mewtwo.db", tmp_root / "mewtwo.db")
        shutil.copytree(ws / "reports", tmp_root / "reports")
        shutil.copytree(ws / "evidence", tmp_root / "evidence")

        manifest = {
            "mewtwo_version": "0.1.0",
            "workspace_slug": slug,
            "exported_at": datetime.utcnow().isoformat(),
            "files": ["mewtwo.db", "reports/", "evidence/"],
        }
        (tmp_root / "manifest.json").write_text(json.dumps(manifest, indent=2))

        with tarfile.open(dest, "w:gz") as tar:
            tar.add(tmp_root, arcname="mewtwo-export")
```

**Why `tempfile.TemporaryDirectory`?** Building the archive structure in a temp dir
means the final `tarfile.open` gets a clean tree — no partial files if the copy
fails mid-way. The temp dir is automatically cleaned up when the `with` block exits.

**Why `arcname="mewtwo-export"`?** `tar.add(tmp_root, arcname="mewtwo-export")` sets
the root path inside the archive. Without `arcname`, the archive would contain the
full temp path like `/tmp/abc123/mewtwo-export/...`. With it, extracting always
produces `mewtwo-export/` regardless of where the archive was created.

**`"w:gz"`** — `w` = write, `gz` = gzip compression. The `.mewtwo` extension is
just a convention — it's a standard `.tar.gz` internally.

### Import: validation before extraction

```python
def import_workspace(archive: Path, workspaces_dir: Path, activate: bool = True) -> str:
    if not tarfile.is_tarfile(archive):
        raise ValueError("Not a valid .mewtwo archive")

    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(tmp_path)

    extracted_root = tmp_path / "mewtwo-export"
    if not extracted_root.exists():
        raise ValueError("Archive does not contain mewtwo-export directory.")

    manifest = json.loads((extracted_root / "manifest.json").read_text())
    slug = manifest.get("workspace_slug", archive.stem.split("_")[0])

    ws_dest = workspaces_dir / slug
    if ws_dest.exists():
        raise FileExistsError(f"Workspace '{slug}' already exists. Use --overwrite.")

    ws_dest.mkdir(parents=True)
    shutil.copy2(db_src, ws_dest / "mewtwo.db")
    shutil.copytree(reports_src, ws_dest / "reports", dirs_exist_ok=True)
    shutil.copytree(evidence_src, ws_dest / "evidence", dirs_exist_ok=True)
```

Validation happens **before** any files are written to the workspace directory:
1. `tarfile.is_tarfile()` — rejects non-tar files early
2. `extracted_root.exists()` — confirms the archive has the expected structure
3. `manifest.json` exists — confirms it was created by Mewtwo
4. `ws_dest.exists()` check — refuses to overwrite without explicit `--overwrite`

`slug` falls back to `archive.stem.split("_")[0]` — extracts the part before the
timestamp in `myengagement_20240101_120000.mewtwo`.

`dirs_exist_ok=True` in `shutil.copytree` is Python 3.8+. It allows the destination
to already exist (it's created empty above) instead of raising `FileExistsError`.

### CLI commands

```python
# cli.py

@cli.command("export")
@click.option("--output", type=click.Path())
def export_cmd(output):
    ws = config.require_active_workspace()
    workspace_io.export_workspace(ws, Path(output) if output else None)

@cli.command("import")
@click.argument("archive", type=click.Path(exists=True))
@click.option("--overwrite", is_flag=True)
def import_cmd(archive, overwrite):
    workspaces_dir = config.mewtwo_home() / "workspaces"
    try:
        slug = workspace_io.import_workspace(Path(archive), workspaces_dir)
        config.set_active_workspace(slug)
    except FileExistsError as e:
        if overwrite:
            shutil.rmtree(workspaces_dir / slug)
            workspace_io.import_workspace(Path(archive), workspaces_dir)
        else:
            error(str(e))

@cli.command("dashboard")
def dashboard_cmd():
    from .tui import launch_dashboard
    launch_dashboard()
```

`mewtwo export` → packs the active workspace.
`mewtwo import archive.mewtwo` → unpacks and activates.
`mewtwo dashboard` → launches the Textual TUI.

`config.require_active_workspace()` raises an error with a helpful message if no
workspace is active — prevents silent failures when running commands without `mewtwo use`.
