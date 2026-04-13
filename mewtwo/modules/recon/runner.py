"""Recon orchestrator — runs all steps and persists results."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ...db import get_db
from ...models.target import Target
from ...storage.recon import ReconRepository
from ...utils.console import console, info, success
from .subdomains import run_subdomain_enum
from .ports import scan_ports
from .tech import fingerprint_url
from .crawler import crawl
from .js_analyzer import analyze_page_js
from .wayback import fetch_wayback_urls


async def run_full_recon(
    target: Target,
    db_path: Path,
    scope_patterns: list[str],
    steps: set[str] | None = None,
    passive_only: bool = False,
    use_ai: bool = True,
) -> dict:
    """Run all recon steps. Returns summary counts dict."""
    if steps is None:
        steps = {"subdomains", "ports", "tech", "urls", "js", "wayback"}

    db = get_db(db_path)
    repo = ReconRepository(db)
    domain = target.slug.replace("-", ".")  # Best-effort; callers should pass root domain

    summary = {
        "subdomains": 0, "ports": 0, "technologies": 0, "urls": 0, "js_secrets": 0, "wayback_urls": 0
    }

    # 1. Subdomain enum
    if "subdomains" in steps:
        subs = await run_subdomain_enum(target.id, domain, passive_only=passive_only)
        for s in subs:
            repo.upsert_subdomain(s)
        summary["subdomains"] = len(subs)
        success(f"Subdomains: {len(subs)} discovered")

    # 2. Port scanning alive subdomains
    if "ports" in steps:
        alive_subs = repo.subdomains_for(target.id)
        alive_hosts = [s["hostname"] for s in alive_subs if s.get("is_alive")][:10]
        all_ports = []
        for host in alive_hosts:
            ports = await scan_ports(target.id, host)
            all_ports.extend(ports)
            for p in ports:
                repo.upsert_port(p)
        summary["ports"] = len(all_ports)
        if all_ports:
            success(f"Ports: {len(all_ports)} open across {len(alive_hosts)} hosts")

    # 3. Technology fingerprinting
    if "tech" in steps:
        alive_subs = repo.subdomains_for(target.id)
        alive_hosts = [s["hostname"] for s in alive_subs if s.get("is_alive")]
        all_techs = []
        for host in alive_hosts[:20]:
            for scheme in ("https", "http"):
                techs = await fingerprint_url(target.id, f"{scheme}://{host}")
                if techs:
                    for t in techs:
                        repo.upsert_tech(t)
                    all_techs.extend(techs)
                    break
        summary["technologies"] = len(all_techs)
        if all_techs:
            success(f"Technologies: {len(all_techs)} fingerprinted")

    # 4. URL crawling
    if "urls" in steps:
        seed = f"https://{domain}"
        urls = await crawl(
            target.id,
            seed,
            depth=3,
            scope_patterns=scope_patterns,
        )
        for u in urls:
            repo.upsert_url(u)
        summary["urls"] = len(urls)
        success(f"URLs: {len(urls)} discovered")

    # 5. Wayback Machine URL harvesting
    if "wayback" in steps:
        wb_urls = await fetch_wayback_urls(target.id, domain, include_subdomains=True)
        for u in wb_urls:
            repo.upsert_url(u)
        summary["wayback_urls"] = len(wb_urls)
        if wb_urls:
            success(f"Wayback Machine: {len(wb_urls)} historical URLs")

    # 6. JS analysis
    if "js" in steps:
        all_secrets = []
        alive_subs = repo.subdomains_for(target.id)
        alive_hosts = [s["hostname"] for s in alive_subs if s.get("is_alive")][:10]
        for host in alive_hosts:
            secrets = await analyze_page_js(target.id, f"https://{host}")
            for s in secrets:
                repo.upsert_js_secret(s)
            all_secrets.extend(secrets)
        summary["js_secrets"] = len(all_secrets)
        if all_secrets:
            success(f"JS secrets/endpoints: {len(all_secrets)} found")

    return summary
