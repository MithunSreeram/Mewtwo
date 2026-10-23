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
@click.option("--tier", type=click.Choice(["safe", "normal", "aggressive"]),
              default="normal", help="Payload safety tier (default: normal)")
@click.option("--rate", type=float, default=None,
              help="Max requests/second (default from MEWTWO_RATE_LIMIT, 0=unlimited)")
@click.option("--no-scope-enforce", is_flag=True,
              help="Disable request-time scope enforcement (NOT recommended)")
@click.option("--auth-cookie", default=None, help="Cookie header for authenticated scan")
@click.option("--auth-bearer", default=None, help="Bearer token for authenticated scan")
@click.option("--auth-header", default=None, help="Extra auth header 'Name: value'")
def run_hunt_cmd(category, vector_id, check_names, no_ai, tier, rate,
                 no_scope_enforce, auth_cookie, auth_bearer, auth_header):
    """Hunt all unchecked attack vectors."""
    from .runner import run_hunt
    from .safety import SafetyTier
    from ...storage.targets import ScopeRepository

    ws, db, target_row = _get_workspace_and_db()

    checks_list = [c.strip() for c in check_names.split(",")] if check_names else None

    # Gather in-scope patterns for request-time enforcement.
    scope_rows = ScopeRepository(db).for_target(target_row["id"])
    scope_patterns = [r["pattern"] for r in scope_rows if r.get("scope_type") == "in_scope"]
    if not scope_patterns and not no_scope_enforce:
        info("No in-scope patterns defined — scope enforcement is a no-op. "
             "Add some with [bold]mewtwo scope add '*.domain'[/bold].")

    resolved_rate = rate if rate is not None else config.rate_limit()
    auth = config.build_auth(auth_cookie, auth_bearer, auth_header)

    findings = asyncio.run(run_hunt(
        target_id=target_row["id"],
        db_path=config.db_path(ws),
        evidence_dir=config.evidence_dir(ws),
        category_filter=category,
        vector_id=vector_id,
        check_names=checks_list,
        use_ai=not no_ai,
        tier=SafetyTier(tier),
        scope_patterns=scope_patterns,
        rate=resolved_rate,
        auth=auth,
        enforce_scope=not no_scope_enforce,
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


@hunt_group.command("nuclei")
@click.option("--severity", help="Comma-separated nuclei severities (e.g. critical,high)")
@click.option("--target", "targets", multiple=True, help="Explicit target URL(s); repeatable")
def nuclei_cmd(severity, targets):
    """Run the nuclei scanner against alive hosts and import results as findings."""
    from .nuclei import run_nuclei, nuclei_available
    from ...storage.recon import ReconRepository
    from ...storage.findings import FindingRepository

    if not nuclei_available():
        error("nuclei not found on PATH. Install: "
              "https://github.com/projectdiscovery/nuclei")
        raise SystemExit(1)

    ws, db, target_row = _get_workspace_and_db()
    recon = ReconRepository(db)
    findings_repo = FindingRepository(db)

    scan_targets = list(targets)
    if not scan_targets:
        subs = recon.subdomains_for(target_row["id"])
        scan_targets = [f"https://{s['hostname']}" for s in subs if s.get("is_alive")]

    if not scan_targets:
        info("No alive targets. Run recon first or pass --target.")
        return

    findings = asyncio.run(run_nuclei(target_row["id"], scan_targets, severities=severity))
    for f in findings:
        findings_repo.upsert(f)

    if findings:
        t = Table("Severity", "Title", "URL")
        for f in findings:
            t.add_row(f.severity.value, f.title[:50], f.url[:50])
        console.print(t)


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
