"""Subdomain enumeration — passive (crt.sh, HackerTarget) + active (subfinder)."""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime

import httpx

from ...models.recon import Subdomain
from ...utils.console import console, info, warn
from ...utils.process import run, tool_available


async def enumerate_passive(domain: str) -> list[str]:
    """Collect subdomains from passive sources. Returns deduplicated hostname list."""
    results: set[str] = set()

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        # crt.sh
        try:
            resp = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{domain}") or sub == domain:
                            results.add(sub.lower())
        except Exception as e:
            warn(f"crt.sh failed: {e}")

        # HackerTarget
        try:
            resp = await client.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}"
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts and parts[0].strip():
                        results.add(parts[0].strip().lower())
        except Exception as e:
            warn(f"HackerTarget failed: {e}")

    return sorted(results)


async def enumerate_active(domain: str) -> list[str]:
    """Use subfinder if available."""
    if not tool_available("subfinder"):
        return []
    info("Running subfinder...")
    try:
        _, stdout, _ = await run("subfinder", "-d", domain, "-silent", timeout=120)
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    except Exception as e:
        warn(f"subfinder failed: {e}")
        return []


async def probe_alive(hostname: str) -> tuple[bool, int | None]:
    """HTTP probe to check if subdomain is alive."""
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"{scheme}://{hostname}", headers={"User-Agent": "Mozilla/5.0"})
                return True, resp.status_code
        except Exception:
            continue
    return False, None


async def run_subdomain_enum(
    target_id: str,
    domain: str,
    passive_only: bool = False,
) -> list[Subdomain]:
    """Full subdomain enumeration pipeline. Returns Subdomain model list."""
    info(f"Enumerating subdomains for {domain}...")

    all_hosts: set[str] = set()

    passive = await enumerate_passive(domain)
    all_hosts.update(passive)
    console.print(f"  [dim]Passive sources: {len(passive)} subdomains[/dim]")

    if not passive_only:
        active = await enumerate_active(domain)
        all_hosts.update(active)
        if active:
            console.print(f"  [dim]subfinder: {len(active)} subdomains[/dim]")

    # Always include the root domain
    all_hosts.add(domain)

    info(f"Probing {len(all_hosts)} hosts for liveness...")
    subs: list[Subdomain] = []

    async def probe_and_build(hostname: str) -> Subdomain:
        alive, code = await probe_alive(hostname)
        return Subdomain(
            id=str(uuid.uuid4()),
            target_id=target_id,
            hostname=hostname,
            sources=["passive"] if hostname in passive else ["active"],
            is_alive=alive,
            status_code=code,
            discovered_at=datetime.utcnow(),
        )

    # Concurrent probing with semaphore
    sem = asyncio.Semaphore(30)

    async def bounded_probe(hostname: str) -> Subdomain:
        async with sem:
            return await probe_and_build(hostname)

    subs = await asyncio.gather(*[bounded_probe(h) for h in all_hosts])
    alive_count = sum(1 for s in subs if s.is_alive)
    console.print(f"  [success]{alive_count}/{len(subs)} hosts alive[/success]")
    return list(subs)
