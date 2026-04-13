"""mewtwo ai — interactive AI interface commands."""

from __future__ import annotations

import click
from rich.live import Live
from rich.markdown import Markdown
from rich.prompt import Prompt

from ... import config
from ...utils.console import console, error


def _get_client():
    from .client import AIClient
    try:
        return AIClient()
    except RuntimeError as e:
        error(str(e))
        raise SystemExit(1)


@click.group("ai")
def ai_group():
    """AI-powered analysis and assistance."""


@ai_group.command("ask")
@click.argument("question", nargs=-1, required=True)
@click.option("--context", type=click.Choice(["recon", "surface", "findings", "all"]), default="all")
@click.option("--no-stream", is_flag=True)
def ask_cmd(question, context, no_stream):
    """Ask a one-shot question with workspace context."""
    from ...config import db_path, active_workspace
    client = _get_client()

    ws = active_workspace()
    workspace_ctx = client.workspace_context_snippet(db_path(ws) if ws else None)

    q = " ".join(question)
    if no_stream:
        answer = client.ask(q, context=workspace_ctx, stream=False)
        console.print(Markdown(answer))
    else:
        console.print()
        with Live(console=console, refresh_per_second=15) as live:
            full = ""
            for chunk in client.ask(q, context=workspace_ctx, stream=True):
                full += chunk
                live.update(Markdown(full))
        console.print()


@ai_group.command("chat")
@click.option("--context", type=click.Choice(["recon", "surface", "findings", "all"]), default="all")
def chat_cmd(context):
    """Interactive chat with persistent conversation history."""
    from ...config import db_path, active_workspace
    from .prompts import ask_system

    client = _get_client()
    ws = active_workspace()
    workspace_ctx = client.workspace_context_snippet(db_path(ws) if ws else None)
    system = ask_system(workspace_ctx)
    history: list[dict] = []

    console.print("[info]Mewtwo AI Chat[/info] — type [dim]exit[/dim] or [dim]quit[/dim] to leave\n")

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]you[/bold cyan]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting chat.[/dim]")
            break

        if user_input.strip().lower() in ("exit", "quit", "q"):
            break

        history.append({"role": "user", "content": user_input})

        console.print("\n[bold magenta]mewtwo[/bold magenta]")
        with Live(console=console, refresh_per_second=15) as live:
            full = ""
            for chunk in client.stream(system=system, messages=history):
                full += chunk
                live.update(Markdown(full))

        history.append({"role": "assistant", "content": full})
        console.print()


@ai_group.command("analyze")
@click.option("--phase", type=click.Choice(["recon", "surface", "hunt", "all"]), default="all")
def analyze_cmd(phase):
    """Run a full AI analysis of the current workspace."""
    from ...config import db_path, require_active_workspace
    from ...db import get_db
    from ...storage import ReconRepository, SurfaceRepository, FindingRepository

    ws = require_active_workspace()
    db = get_db(db_path(ws))
    client = _get_client()

    if phase in ("recon", "all"):
        console.print("[info]Analyzing recon data...[/info]")
        recon = ReconRepository(db)
        target_rows = list(db["targets"].rows)
        if not target_rows:
            error("No target found in workspace.")
            return
        tid = target_rows[0]["id"]
        subs = recon.subdomains_for(tid)
        techs = recon.techs_for(tid)
        secrets = recon.js_secrets_for(tid)
        result = client.analyze_recon(subs, techs, secrets, db_path(ws))
        vectors = result.get("vectors", [])
        console.print(f"[success]AI identified {len(vectors)} attack vector(s) from recon data.[/success]")
        for v in vectors:
            console.print(f"  [{v.get('risk_rating', 'medium')}]{v['title']}[/] — {v['url']}")

    if phase in ("surface", "all"):
        console.print("[info]Analyzing attack surface...[/info]")
        surf = SurfaceRepository(db)
        target_rows = list(db["targets"].rows)
        if target_rows:
            tid = target_rows[0]["id"]
            vectors = surf.for_target(tid)
            console.print(f"[info]{len(vectors)} attack vector(s) in surface map.[/info]")

    if phase in ("hunt", "all"):
        console.print("[info]Reviewing findings...[/info]")
        findings_repo = FindingRepository(db)
        target_rows = list(db["targets"].rows)
        if target_rows:
            tid = target_rows[0]["id"]
            findings = findings_repo.for_target(tid)
            console.print(f"[info]{len(findings)} finding(s) on record.[/info]")
