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
              type=click.Choice(["subdomains", "ports", "tech", "urls", "js", "wayback"]))
@click.option("--passive-only", is_flag=True, help="Skip active enumeration tools")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis pass")
@click.option("--force", is_flag=True, help="Redo all steps, ignoring prior checkpoints")
def run_recon(domain, only, passive_only, no_ai, force):
    """Run all recon steps against the active target (resumable by default)."""
    from ...models.target import Target
    from .runner import run_full_recon, clear_checkpoints

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
    if force:
        clear_checkpoints(db, target.id)
        info("Cleared recon checkpoints — running all steps fresh.")
    info(f"Starting recon for [bold]{target.name}[/bold] ({root_domain})")

    summary = asyncio.run(run_full_recon(
        target=target,
        db_path=config.db_path(ws),
        scope_patterns=scope_patterns,
        steps=steps,
        passive_only=passive_only,
        use_ai=not no_ai,
        resume=not force,
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


@recon_group.command("wayback")
@click.option("--domain", "-d", required=True, help="Domain to query")
@click.option("--no-subdomains", is_flag=True, help="Only query exact domain, not *.domain")
@click.option("--limit", default=10000, show_default=True, help="Max URLs to fetch")
def wayback_cmd(domain, no_subdomains, limit):
    """Harvest historical URLs from the Wayback Machine."""
    from .wayback import fetch_wayback_urls

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    urls = asyncio.run(fetch_wayback_urls(
        target_row["id"], domain,
        include_subdomains=not no_subdomains,
        limit=limit,
    ))
    for u in urls:
        repo.upsert_url(u)

    if not urls:
        info("No historical URLs found.")
        return

    table = Table("URL", "Status", "Params", "Date", title=f"Wayback URLs — {domain}")
    for u in urls[:60]:
        table.add_row(
            u.url[:80],
            str(u.status_code or "—"),
            str(len(u.parameters)),
            u.discovered_at.strftime("%Y-%m-%d") if u.discovered_at else "—",
        )
    console.print(table)
    if len(urls) > 60:
        console.print(f"[dim]... and {len(urls) - 60} more[/dim]")
    success(f"{len(urls)} historical URLs saved.")


@recon_group.command("params")
@click.argument("url")
@click.option("--save", is_flag=True, help="Merge discovered params into the stored URL row")
def params_cmd(url, save):
    """Discover hidden/unlinked query parameters via reflection."""
    from .param_miner import discover_params

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)

    found = asyncio.run(discover_params(url))
    if not found:
        info("No reflected parameters discovered.")
        return

    table = Table("Parameter", title=f"Discovered Parameters — {url}")
    for p in found:
        table.add_row(p)
    console.print(table)
    success(f"{len(found)} parameter(s) discovered.")

    if save:
        # Merge into an existing URL row if present, else create one.
        existing = [u for u in repo.urls_for(target_row["id"]) if u["url"] == url]
        from ...models.recon import DiscoveredURL
        if existing:
            row = existing[0]
            merged = sorted(set(row.get("parameters", [])) | set(found))
            db["urls"].update(row["id"], {"parameters_json": __import__("json").dumps(merged)})
        else:
            repo.upsert_url(DiscoveredURL(
                target_id=target_row["id"], url=url, parameters=found, source="param_miner",
            ))
        success("Saved to URL store (feeds surface mapping).")


@recon_group.command("favicon")
@click.argument("url")
def favicon_cmd(url):
    """Compute the Shodan-style favicon hash for infrastructure pivoting."""
    from .favicon import fetch_favicon_hash, identify

    result = asyncio.run(fetch_favicon_hash(url))
    if not result:
        info("No favicon found or fetch failed.")
        return
    hash_value, favicon_url = result
    product = identify(hash_value)
    console.print(f"[bold]Favicon:[/bold] {favicon_url}")
    console.print(f"[bold]mmh3 hash:[/bold] [info]{hash_value}[/info]")
    if product:
        console.print(f"[bold]Known product:[/bold] [yellow]{product}[/yellow]")
    console.print(f"\n[dim]Pivot on Shodan:[/dim] http.favicon.hash:{hash_value}")


@recon_group.command("takeover")
def takeover_cmd():
    """Scan alive subdomains for dangling CNAMEs (subdomain takeover candidates)."""
    from .dns_intel import find_takeover_candidates

    ws, db, target_row = _get_workspace_and_target()
    repo = ReconRepository(db)
    subs = repo.subdomains_for(target_row["id"])
    hostnames = [s["hostname"] for s in subs]
    if not hostnames:
        info("No subdomains yet. Run [bold]mewtwo recon subdomains -d <domain>[/bold] first.")
        return

    candidates = find_takeover_candidates(hostnames)
    if not candidates:
        info("No takeover candidates found (or dnspython not installed).")
        return

    table = Table("Hostname", "CNAME", "Service", title="Subdomain Takeover Candidates")
    for c in candidates:
        table.add_row(c["hostname"], c["cname"], f"[yellow]{c['service']}[/yellow]")
    console.print(table)
    success(f"{len(candidates)} candidate(s) — confirm the resource is unclaimed, "
            f"then run [bold]mewtwo hunt[/bold] with the subdomain_takeover check.")


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
