"""mewtwo surface — attack surface mapping commands."""

from __future__ import annotations

import asyncio
import uuid

import click
from rich.table import Table

from ... import config
from ...db import get_db
from ...models.surface import AttackVector, VectorCategory
from ...storage.surface import SurfaceRepository
from ...utils.console import console, error, info, success


def _get_workspace_and_db():
    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target in workspace.")
        raise SystemExit(1)
    return ws, db, targets[0]


@click.group("surface")
def surface_group():
    """Attack surface mapping — identify and manage attack vectors."""


@surface_group.command("map")
@click.option("--no-ai", is_flag=True)
def map_cmd(no_ai):
    """Map attack surface from current recon data."""
    from .mapper import run_surface_map

    ws, db, target_row = _get_workspace_and_db()
    vectors = asyncio.run(run_surface_map(
        target_id=target_row["id"],
        db_path=config.db_path(ws),
        use_ai=not no_ai,
    ))
    _print_vectors_table(vectors)


@surface_group.command("show")
@click.option("--category", help="Filter by category")
@click.option("--risk", type=click.Choice(["critical", "high", "medium", "low"]))
def show_cmd(category, risk):
    """Show current attack vectors."""
    ws, db, target_row = _get_workspace_and_db()
    repo = SurfaceRepository(db)
    rows = repo.for_target(target_row["id"], category=category)

    if risk:
        rows = [r for r in rows if r.get("risk_rating") == risk]

    if not rows:
        info("No attack vectors found. Run [bold]mewtwo surface map[/bold] first.")
        return

    t = Table("ID", "Category", "Title", "Risk", "URL", "Checked")
    for row in rows:
        t.add_row(
            row["id"][:8],
            row["category"],
            row["title"][:50],
            _risk_style(row.get("risk_rating", "medium")),
            row["url"][:50],
            "[green]✓[/green]" if row.get("checked") else "[dim]○[/dim]",
        )
    console.print(t)
    console.print(f"[dim]{len(rows)} vector(s) total[/dim]")


@surface_group.command("add")
@click.option("--title", required=True)
@click.option("--url", required=True)
@click.option("--category", required=True,
              type=click.Choice([c.value for c in VectorCategory]))
@click.option("--risk", default="medium",
              type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--description", default="")
@click.option("--rationale", default="")
def add_cmd(title, url, category, risk, description, rationale):
    """Manually add an attack vector."""
    ws, db, target_row = _get_workspace_and_db()
    repo = SurfaceRepository(db)

    vector = AttackVector(
        target_id=target_row["id"],
        category=VectorCategory(category),
        title=title,
        description=description,
        url=url,
        risk_rating=risk,
        rationale=rationale,
    )
    repo.upsert(vector)
    success(f"Vector added: {vector.id[:8]} — {title}")


@surface_group.command("note")
@click.argument("vector_id")
@click.argument("text")
def note_cmd(vector_id, text):
    """Append a note to a vector's description."""
    ws, db, target_row = _get_workspace_and_db()
    repo = SurfaceRepository(db)

    rows = list(db["attack_vectors"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{vector_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Vector not found: {vector_id}")
        raise SystemExit(1)

    row = rows[0]
    new_desc = (row["description"] or "") + f"\n\nNote: {text}"
    db["attack_vectors"].update(row["id"], {"description": new_desc})
    success(f"Note added to vector {row['id'][:8]}.")


def _print_vectors_table(vectors) -> None:
    if not vectors:
        info("No vectors found.")
        return
    t = Table("Category", "Title", "Risk", "URL")
    for v in vectors:
        cat = v.category.value if hasattr(v, "category") else v.get("category", "")
        title = v.title if hasattr(v, "title") else v.get("title", "")
        risk = v.risk_rating if hasattr(v, "risk_rating") else v.get("risk_rating", "medium")
        url = v.url if hasattr(v, "url") else v.get("url", "")
        t.add_row(cat, title[:50], _risk_style(risk), url[:50])
    console.print(t)


def _risk_style(risk: str) -> str:
    styles = {
        "critical": "[bold red]critical[/bold red]",
        "high": "[red]high[/red]",
        "medium": "[yellow]medium[/yellow]",
        "low": "[blue]low[/blue]",
    }
    return styles.get(risk.lower(), risk)
