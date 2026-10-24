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


def _checkpoint_done(db, target_id: str, step: str) -> bool:
    """Has this recon step already completed for the target? (resumable runs)"""
    if "recon_checkpoints" not in db.table_names():
        return False
    rows = list(db["recon_checkpoints"].rows_where(
        "target_id = ? AND step = ?", [target_id, step]
    ))
    return bool(rows)


def _mark_checkpoint(db, target_id: str, step: str) -> None:
    from datetime import datetime
    db["recon_checkpoints"].upsert({
        "id": f"{target_id}:{step}",
        "target_id": target_id,
        "step": step,
        "completed_at": datetime.utcnow().isoformat(),
    }, pk="id", alter=True)


def clear_checkpoints(db, target_id: str) -> None:
    """Wipe recon checkpoints so a run starts fresh."""
    if "recon_checkpoints" in db.table_names():
        db["recon_checkpoints"].delete_where("target_id = ?", [target_id])


async def run_full_recon(
    target: Target,
    db_path: Path,
    scope_patterns: list[str],
    steps: set[str] | None = None,
    passive_only: bool = False,
    use_ai: bool = True,
    resume: bool = True,
    on_progress=None,
) -> dict:
    """Run all recon steps. Returns summary counts dict.

    With ``resume=True`` (default), steps already completed in a previous run are skipped —
    so an interrupted recon can be re-run without redoing finished work.

    ``on_progress``, if given, is called with a dict at each step boundary (used by the web
    UI for live updates). It never changes behaviour and is a no-op for the CLI.
    """
    if steps is None:
        steps = {"subdomains", "ports", "tech", "urls", "js", "wayback"}

    def _progress(**kw):
        if on_progress:
            on_progress(kw)

    db = get_db(db_path)
    repo = ReconRepository(db)

    def _should_run(step: str) -> bool:
        if step not in steps:
            return False
        if resume and _checkpoint_done(db, target.id, step):
            info(f"Skipping '{step}' — already completed (use --force to redo)")
            return False
        return True

    domain = target.slug.replace("-", ".")  # Best-effort; callers should pass root domain

    summary = {
        "subdomains": 0, "ports": 0, "technologies": 0, "urls": 0, "js_secrets": 0, "wayback_urls": 0
    }

    # 1. Subdomain enum
    if _should_run("subdomains"):
        subs = await run_subdomain_enum(target.id, domain, passive_only=passive_only)
        for s in subs:
            repo.upsert_subdomain(s)
        summary["subdomains"] = len(subs)
        success(f"Subdomains: {len(subs)} discovered")
        _mark_checkpoint(db, target.id, "subdomains")
        _progress(phase="subdomains", count=summary["subdomains"])

    # 2. Port scanning alive subdomains
    if _should_run("ports"):
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
        _mark_checkpoint(db, target.id, "ports")
        _progress(phase="ports", count=summary["ports"])

    # 3. Technology fingerprinting
    if _should_run("tech"):
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
        _mark_checkpoint(db, target.id, "tech")
        _progress(phase="tech", count=summary["technologies"])

    # 4. URL crawling
    if _should_run("urls"):
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
        _mark_checkpoint(db, target.id, "urls")
        _progress(phase="urls", count=summary["urls"])

    # 5. Wayback Machine URL harvesting
    if _should_run("wayback"):
        wb_urls = await fetch_wayback_urls(target.id, domain, include_subdomains=True)
        for u in wb_urls:
            repo.upsert_url(u)
        summary["wayback_urls"] = len(wb_urls)
        if wb_urls:
            success(f"Wayback Machine: {len(wb_urls)} historical URLs")
        _mark_checkpoint(db, target.id, "wayback")
        _progress(phase="wayback", count=summary["wayback_urls"])

    # 6. JS analysis
    if _should_run("js"):
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
        _mark_checkpoint(db, target.id, "js")
        _progress(phase="js", count=summary["js_secrets"])

    return summary
