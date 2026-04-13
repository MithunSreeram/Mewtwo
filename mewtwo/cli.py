"""Mewtwo CLI — root command group and workspace management."""

from __future__ import annotations

import click
from rich.table import Table

from . import __version__
from . import config
from .db import get_db
from .utils.console import console, error, info, success, warn
from .utils.validators import slugify


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="mewtwo")
def cli():
    """Mewtwo — AI-assisted bug bounty toolkit.

    \b
    Workflow:
      mewtwo init <target>     Create a workspace
      mewtwo recon run         Enumerate attack surface
      mewtwo surface map       Map attack vectors
      mewtwo hunt run          Hunt for vulnerabilities
      mewtwo findings list     Review findings
      mewtwo report generate   Generate report
    """


# ---------------------------------------------------------------------------
# Workspace management
# ---------------------------------------------------------------------------

@cli.command("init")
@click.argument("name")
@click.option("--platform", default="", help="e.g. hackerone, bugcrowd, private")
@click.option("--program-url", default="")
@click.option("--domain", "-d", default="", help="Root domain (defaults to slug)")
def init_cmd(name, platform, program_url, domain):
    """Create a new workspace and set it as active."""
    from .models.target import Target
    from .storage.targets import TargetRepository

    slug = slugify(name)
    ws = config.workspace_path(slug)

    if ws.exists():
        warn(f"Workspace '{slug}' already exists. Switching to it.")
        config.set_active_workspace(slug)
        return

    ws.mkdir(parents=True, exist_ok=True)
    (ws / "reports").mkdir(exist_ok=True)
    (ws / "evidence").mkdir(exist_ok=True)

    db = get_db(config.db_path(ws))

    target = Target(
        name=name,
        slug=slug,
        platform=platform,
        program_url=program_url,
    )

    # Store root domain hint on the target row
    repo = TargetRepository(db)
    repo.upsert(target)

    # Patch: add root_domain column if needed and store
    try:
        db["targets"].add_column("root_domain", str, not_null=False)
    except Exception:
        pass
    db["targets"].update(target.id, {"root_domain": domain or slug})

    config.set_active_workspace(slug)
    success(f"Workspace created: [bold]{slug}[/bold]")
    console.print(f"  DB: [dim]{config.db_path(ws)}[/dim]")
    console.print(f"\nNext: [bold]mewtwo scope add '*.<domain>' --type in[/bold]")
    console.print(f"Then: [bold]mewtwo recon run -d {domain or slug}[/bold]")


@cli.command("use")
@click.argument("name")
def use_cmd(name):
    """Switch active workspace."""
    slug = slugify(name)
    try:
        config.set_active_workspace(slug)
        success(f"Active workspace → [bold]{slug}[/bold]")
    except FileNotFoundError:
        error(f"Workspace '{slug}' not found. Run [bold]mewtwo list[/bold] to see available.")
        raise SystemExit(1)


@cli.command("list")
def list_cmd():
    """List all workspaces."""
    ws_dir = config.workspaces_dir()
    active = config.active_workspace()

    workspaces = [d for d in ws_dir.iterdir() if d.is_dir()]
    if not workspaces:
        info("No workspaces yet. Run [bold]mewtwo init <target>[/bold].")
        return

    t = Table("", "Name", "Target", "Findings", "DB Size")
    for ws in sorted(workspaces):
        is_active = active and ws.resolve() == active.resolve()
        marker = "[green]▶[/green]" if is_active else " "
        db_p = ws / "mewtwo.db"
        findings_count = 0
        target_name = ws.name

        if db_p.exists():
            import sqlite_utils
            db = sqlite_utils.Database(db_p)
            try:
                targets = list(db["targets"].rows)
                if targets:
                    target_name = targets[0]["name"]
                findings_count = db["findings"].count if "findings" in db.table_names() else 0
            except Exception:
                pass
            size = f"{db_p.stat().st_size // 1024}KB"
        else:
            size = "—"

        t.add_row(marker, ws.name, target_name, str(findings_count), size)

    console.print(t)


@cli.command("status")
def status_cmd():
    """Show current workspace status and phase summary."""
    ws = config.active_workspace()
    if not ws:
        info("No active workspace. Run [bold]mewtwo init <target>[/bold].")
        return

    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("Workspace has no target record.")
        return

    target = targets[0]
    tid = target["id"]

    # Counts
    def count(table: str, where: str = "", params: list = []) -> int:
        if table not in db.table_names():
            return 0
        if where:
            return db[table].count_where(where, params)
        return db[table].count

    subs_total = count("subdomains", "target_id = ?", [tid])
    subs_alive = count("subdomains", "target_id = ? AND is_alive = 1", [tid])
    urls = count("urls", "target_id = ?", [tid])
    vectors = count("attack_vectors", "target_id = ?", [tid])
    vectors_checked = count("attack_vectors", "target_id = ? AND checked = 1", [tid])
    findings = count("findings", "target_id = ?", [tid])

    console.print(f"\n[bold]Active Workspace:[/bold] {ws.name}")
    console.print(f"[bold]Target:[/bold] {target['name']}")
    if target.get("platform"):
        console.print(f"[bold]Platform:[/bold] {target['platform']}")
    if target.get("program_url"):
        console.print(f"[bold]Program:[/bold] {target['program_url']}")

    console.print("\n[bold]Progress:[/bold]")
    console.print(f"  Subdomains:    {subs_alive}/{subs_total} alive")
    console.print(f"  URLs:          {urls}")
    console.print(f"  Attack Vectors:{vectors_checked}/{vectors} checked")
    console.print(f"  Findings:      {findings}")

    # Phase recommendation
    console.print()
    if subs_total == 0:
        console.print("[dim]Suggested next step:[/dim] [bold]mewtwo recon run[/bold]")
    elif vectors == 0:
        console.print("[dim]Suggested next step:[/dim] [bold]mewtwo surface map[/bold]")
    elif vectors_checked < vectors:
        console.print("[dim]Suggested next step:[/dim] [bold]mewtwo hunt run[/bold]")
    elif findings > 0:
        console.print("[dim]Suggested next step:[/dim] [bold]mewtwo report generate[/bold]")


# ---------------------------------------------------------------------------
# Scope management
# ---------------------------------------------------------------------------

@cli.group("scope")
def scope_group():
    """Manage target scope entries."""


@scope_group.command("add")
@click.argument("pattern")
@click.option("--type", "scope_type",
              type=click.Choice(["in", "out", "info"]), default="in")
@click.option("--notes", default="")
def scope_add(pattern, scope_type, notes):
    """Add a scope entry (e.g. '*.example.com')."""
    from .models.target import ScopeEntry, ScopeType
    from .storage.targets import ScopeRepository

    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target in workspace.")
        raise SystemExit(1)

    type_map = {"in": ScopeType.IN_SCOPE, "out": ScopeType.OUT_OF_SCOPE, "info": ScopeType.INFORMATIONAL}
    entry = ScopeEntry(
        target_id=targets[0]["id"],
        pattern=pattern,
        scope_type=type_map[scope_type],
        notes=notes,
    )
    ScopeRepository(db).add(entry)
    success(f"Scope entry added: [{scope_type}] {pattern}")


@scope_group.command("remove")
@click.argument("pattern")
def scope_remove(pattern):
    """Remove a scope entry."""
    from .storage.targets import ScopeRepository

    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target.")
        raise SystemExit(1)

    ScopeRepository(db).remove(targets[0]["id"], pattern)
    success(f"Scope entry removed: {pattern}")


@scope_group.command("list")
def scope_list():
    """List all scope entries."""
    from .storage.targets import ScopeRepository

    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target.")
        raise SystemExit(1)

    entries = ScopeRepository(db).for_target(targets[0]["id"])
    if not entries:
        info("No scope entries. Run [bold]mewtwo scope add <pattern>[/bold].")
        return

    t = Table("Pattern", "Type", "Notes")
    for e in entries:
        t.add_row(e["pattern"], e["scope_type"], e.get("notes", ""))
    console.print(t)


# ---------------------------------------------------------------------------
# Register module CLIs
# ---------------------------------------------------------------------------

from .modules.recon.cli import recon_group
from .modules.surface.cli import surface_group
from .modules.hunt.cli import hunt_group
from .modules.findings.cli import findings_group
from .modules.report.cli import report_group
from .modules.ai.cli import ai_group

cli.add_command(recon_group)
cli.add_command(surface_group)
cli.add_command(hunt_group)
cli.add_command(findings_group)
cli.add_command(report_group)
cli.add_command(ai_group)
