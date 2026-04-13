"""mewtwo recon — reconnaissance command group."""

from __future__ import annotations

import asyncio

import click
from rich.table import Table

from ... import config
from ...db import get_db
from ...storage.recon import ReconRepository
from ...storage.targets import TargetRepository
from ...utils.console import console, error, info, success


def _get_workspace_and_target():
    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target in workspace. Run [bold]mewtwo init[/bold] first.")
        raise SystemExit(1)
    return ws, db, targets[0]


@click.group("recon")
def recon_group():
    """Reconnaissance — subdomains, ports, tech, URLs, JS analysis."""


@recon_group.command("run")
@click.option("--domain", "-d", help="Root domain to recon (defaults to target slug)")
@click.option("--only", multiple=True,
              type=click.Choice(["subdomains", "ports", "tech", "urls", "js"]))
@click.option("--passive-only", is_flag=True, help="Skip active enumeration tools")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis pass")
def run_recon(domain, only, passive_only, no_ai):
    """Run all recon steps against the active target."""
    from ...models.target import Target
    from .runner import run_full_recon

    ws, db, target_row = _get_workspace_and_target()

    target = Target(
        id=target_row["id"],
        name=target_row["name"],
        slug=target_row["slug"],
        platform=target_row.get("platform", ""),
    )

    root_domain = domain or target_row.get("root_domain") or target.slug

    scope_rows = list(db["scope"].rows_where("target_id = ? AND scope_type = 'in_scope'", [target.id]))
    scope_patterns = [r["pattern"] for r in scope_rows] or [f"*.{root_domain}", root_domain]

    steps = set(only) if only else None
    info(f"Starting recon for [bold]{target.name}[/bold] ({root_domain})")

    summary = asyncio.run(run_full_recon(
        target=target,
        db_path=config.db_path(ws),
        scope_patterns=scope_patterns,
        steps=steps,
        passive_only=passive_only,
        use_ai=not no_ai,
    ))

    console.print("\n[bold]Recon Summary:[/bold]")
    for k, v in summary.items():
        console.print(f"  {k}: [info]{v}[/info]")


@recon_group.command("subdomains")
@click.option("--domain", "-d", required=True, help="Domain to enumerate")
@click.option("--passive-only", is_flag=True)
def subdomains_cmd(domain, passive_only):
    """Enumerate subdomains for a domain."""
    from .subdomains import run_subdomain_enum

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    subs = asyncio.run(run_subdomain_enum(target_row["id"], domain, passive_only=passive_only))
    for s in subs:
        repo.upsert_subdomain(s)

    table = Table("Hostname", "Alive", "Status", title=f"Subdomains — {domain}")
    for s in sorted(subs, key=lambda x: (not x.is_alive, x.hostname)):
        table.add_row(
            s.hostname,
            "[green]✓[/green]" if s.is_alive else "[dim]✗[/dim]",
            str(s.status_code) if s.status_code else "—",
        )
    console.print(table)
    success(f"Saved {len(subs)} subdomains.")


@recon_group.command("ports")
@click.argument("host")
@click.option("--top-ports", default=1000, show_default=True)
def ports_cmd(host, top_ports):
    """Port scan a specific host."""
    from .ports import scan_ports

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    ports = asyncio.run(scan_ports(target_row["id"], host, top_ports=top_ports))
    for p in ports:
        repo.upsert_port(p)

    if not ports:
        info("No open ports found.")
        return

    table = Table("Port", "Protocol", "Service", "Version", title=f"Open Ports — {host}")
    for p in sorted(ports, key=lambda x: x.port):
        table.add_row(str(p.port), p.protocol, p.service, p.version)
    console.print(table)
    success(f"{len(ports)} open ports saved.")


@recon_group.command("tech")
@click.argument("url")
def tech_cmd(url):
    """Fingerprint technologies at a URL."""
    from .tech import fingerprint_url

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    techs = asyncio.run(fingerprint_url(target_row["id"], url))
    for t in techs:
        repo.upsert_tech(t)

    if not techs:
        info("No technologies fingerprinted.")
        return

    table = Table("Technology", "Version", "Category", "Confidence", title=f"Technologies — {url}")
    for t in techs:
        table.add_row(t.name, t.version, t.category, f"{t.confidence}%")
    console.print(table)


@recon_group.command("crawl")
@click.argument("url")
@click.option("--depth", default=3, show_default=True)
@click.option("--scope-only", is_flag=True)
def crawl_cmd(url, depth, scope_only):
    """Crawl from a seed URL."""
    from .crawler import crawl

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    scope_patterns = None
    if scope_only:
        scope_rows = list(db["scope"].rows_where(
            "target_id = ? AND scope_type = 'in_scope'", [target_row["id"]]
        ))
        scope_patterns = [r["pattern"] for r in scope_rows]

    urls = asyncio.run(crawl(target_row["id"], url, depth=depth, scope_patterns=scope_patterns))
    for u in urls:
        repo.upsert_url(u)

    table = Table("URL", "Status", "Params", title=f"Crawl Results — {url}")
    for u in urls[:50]:
        table.add_row(u.url[:80], str(u.status_code or "—"), str(len(u.parameters)))
    console.print(table)
    if len(urls) > 50:
        console.print(f"[dim]... and {len(urls) - 50} more[/dim]")
    success(f"{len(urls)} URLs saved.")


@recon_group.command("js")
@click.argument("url")
def js_cmd(url):
    """Analyze a JavaScript file or page for secrets/endpoints."""
    from .js_analyzer import analyze_js_file, analyze_page_js

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    if url.endswith(".js"):
        secrets = asyncio.run(analyze_js_file(target_row["id"], url))
    else:
        secrets = asyncio.run(analyze_page_js(target_row["id"], url))

    for s in secrets:
        repo.upsert_js_secret(s)

    if not secrets:
        info("No secrets or interesting endpoints found.")
        return

    table = Table("Type", "Value", "Confidence", "Source", title="JS Analysis Results")
    for s in secrets:
        table.add_row(s.secret_type, s.value[:60], s.confidence, s.source_url[:40])
    console.print(table)
    success(f"{len(secrets)} items saved.")


@recon_group.command("show")
@click.option("--type", "data_type",
              type=click.Choice(["subdomains", "ports", "tech", "urls", "js", "all"]),
              default="all")
def show_cmd(data_type):
    """Display recon data for the active target."""
    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)
    tid = target_row["id"]

    if data_type in ("subdomains", "all"):
        subs = repo.subdomains_for(tid)
        if subs:
            t = Table("Hostname", "Alive", "Status", title="Subdomains")
            for s in subs:
                t.add_row(s["hostname"],
                          "[green]✓[/green]" if s.get("is_alive") else "[dim]✗[/dim]",
                          str(s.get("status_code") or "—"))
            console.print(t)

    if data_type in ("ports", "all"):
        ports = repo.ports_for(tid)
        if ports:
            t = Table("Host", "Port", "Protocol", "Service", title="Ports")
            for p in ports:
                t.add_row(p["host"], str(p["port"]), p["protocol"], p["service"])
            console.print(t)

    if data_type in ("tech", "all"):
        techs = repo.techs_for(tid)
        if techs:
            t = Table("Host", "Technology", "Version", "Category", title="Technologies")
            for tech in techs:
                t.add_row(tech["host"], tech["name"], tech.get("version", ""), tech.get("category", ""))
            console.print(t)

    if data_type in ("urls", "all"):
        urls = repo.urls_for(tid)
        if urls:
            t = Table("URL", "Status", "Params", title="Discovered URLs")
            for u in urls[:100]:
                t.add_row(u["url"][:80], str(u.get("status_code") or "—"),
                          str(len(u.get("parameters", []))))
            console.print(t)
            if len(urls) > 100:
                console.print(f"[dim]... and {len(urls) - 100} more[/dim]")

    if data_type in ("js", "all"):
        secrets = repo.js_secrets_for(tid)
        if secrets:
            t = Table("Type", "Value", "Confidence", title="JS Secrets")
            for s in secrets:
                t.add_row(s["secret_type"], s["value"][:60], s.get("confidence", ""))
            console.print(t)
