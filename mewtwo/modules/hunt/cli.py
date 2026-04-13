"""mewtwo hunt — vulnerability hunting commands."""

from __future__ import annotations

import asyncio

import click
from rich.table import Table

from ... import config
from ...db import get_db
from ...utils.console import console, error, info
from .checks import ALL_CHECKS


def _get_workspace_and_db():
    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target in workspace.")
        raise SystemExit(1)
    return ws, db, targets[0]


@click.group("hunt")
def hunt_group():
    """Vulnerability hunting — automated checks against attack vectors."""


@hunt_group.command("run")
@click.option("--category", help="Filter by vector category")
@click.option("--vector-id", help="Hunt a specific vector by ID prefix")
@click.option("--checks", "check_names", help="Comma-separated check names to run")
@click.option("--no-ai", is_flag=True, help="Disable AI triage")
def run_hunt_cmd(category, vector_id, check_names, no_ai):
    """Hunt all unchecked attack vectors."""
    from .runner import run_hunt

    ws, db, target_row = _get_workspace_and_db()

    checks_list = [c.strip() for c in check_names.split(",")] if check_names else None

    findings = asyncio.run(run_hunt(
        target_id=target_row["id"],
        db_path=config.db_path(ws),
        evidence_dir=config.evidence_dir(ws),
        category_filter=category,
        vector_id=vector_id,
        check_names=checks_list,
        use_ai=not no_ai,
    ))

    if findings:
        t = Table("Severity", "Title", "URL", "Status")
        for f in findings:
            t.add_row(
                f.severity.value,
                f.title[:50],
                f.url[:50],
                f.status.value,
            )
        console.print(t)


@hunt_group.command("checks")
def list_checks():
    """List all available hunt checks."""
    t = Table("Name", "Vuln Class", "Description", "Categories")
    for check_cls in ALL_CHECKS:
        t.add_row(
            check_cls.name,
            check_cls.vuln_class,
            check_cls.description,
            ", ".join(check_cls.applicable_categories),
        )
    console.print(t)


@hunt_group.command("payload")
@click.argument("vuln_class")
@click.option("--ai", "use_ai", is_flag=True, help="Generate context-aware payloads with AI")
@click.option("--url", default="", help="Target URL for context")
@click.option("--param", default="", help="Target parameter for context")
def payload_cmd(vuln_class, use_ai, url, param):
    """Show or generate payloads for a vulnerability class."""
    from pathlib import Path

    payload_file = Path(__file__).parent / "payloads" / f"{vuln_class.lower()}.txt"
    if payload_file.exists():
        console.print(f"[info]Static payloads for {vuln_class}:[/info]")
        console.print(payload_file.read_text())

    if use_ai:
        ws = config.active_workspace()
        from ...modules.ai.client import AIClient
        try:
            client = AIClient()
            tech_stack: list[str] = []
            if ws:
                from ...storage.recon import ReconRepository
                db = get_db(config.db_path(ws))
                targets = list(db["targets"].rows)
                if targets:
                    techs = ReconRepository(db).techs_for(targets[0]["id"])
                    tech_stack = [t["name"] for t in techs]

            payloads = client.generate_payloads(vuln_class, url, param, tech_stack)
            console.print(f"\n[info]AI-generated payloads:[/info]")
            for p in payloads:
                console.print(f"  {p}")
        except Exception as e:
            error(f"AI payload generation failed: {e}")


@hunt_group.command("ask")
@click.argument("question", nargs=-1, required=True)
def ask_cmd(question):
    """Ask Claude a hunt-related question."""
    ws = config.active_workspace()
    from ...modules.ai.client import AIClient
    from rich.live import Live
    from rich.markdown import Markdown

    try:
        client = AIClient()
    except RuntimeError as e:
        error(str(e))
        raise SystemExit(1)

    workspace_ctx = client.workspace_context_snippet(
        config.db_path(ws) if ws else None
    )

    q = " ".join(question)
    console.print()
    with Live(console=console, refresh_per_second=15) as live:
        full = ""
        for chunk in client.ask(q, context=workspace_ctx, stream=True):
            full += chunk
            live.update(Markdown(full))
    console.print()
