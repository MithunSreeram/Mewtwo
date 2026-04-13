"""mewtwo findings — finding management commands."""

from __future__ import annotations

import json
from datetime import datetime

import click
from rich.panel import Panel
from rich.table import Table

from ... import config
from ...db import get_db
from ...models.finding import Finding, Severity, FindingStatus, Evidence
from ...storage.findings import FindingRepository
from ...utils.console import console, error, info, success, severity_style


def _get_repo():
    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target in workspace.")
        raise SystemExit(1)
    return ws, db, targets[0], FindingRepository(db)


@click.group("findings")
def findings_group():
    """Finding management — add, view, edit, enrich, and track vulnerabilities."""


@findings_group.command("add")
@click.option("--title", prompt=True)
@click.option("--url", prompt=True)
@click.option("--vuln-class", prompt=True)
@click.option("--severity", prompt=True,
              type=click.Choice([s.value for s in Severity]))
@click.option("--description", default="")
@click.option("--parameter", default="")
def add_cmd(title, url, vuln_class, severity, description, parameter):
    """Interactively add a finding."""
    ws, db, target_row, repo = _get_repo()

    finding = Finding(
        target_id=target_row["id"],
        title=title,
        url=url,
        vuln_class=vuln_class,
        severity=Severity(severity),
        description=description,
        parameter=parameter,
    )
    repo.upsert(finding)
    success(f"Finding added: {finding.id[:8]} — {title}")


@findings_group.command("list")
@click.option("--severity", type=click.Choice([s.value for s in Severity]))
@click.option("--status", type=click.Choice([s.value for s in FindingStatus]))
@click.option("--vuln-class")
def list_cmd(severity, status, vuln_class):
    """List all findings."""
    ws, db, target_row, repo = _get_repo()
    findings = repo.for_target(target_row["id"], severity=severity, status=status)

    if vuln_class:
        findings = [f for f in findings if vuln_class.lower() in f.get("vuln_class", "").lower()]

    if not findings:
        info("No findings. Run [bold]mewtwo hunt run[/bold] or [bold]mewtwo findings add[/bold].")
        return

    t = Table("ID", "Severity", "Title", "Vuln Class", "URL", "Status")
    for f in sorted(findings, key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(
            x.get("severity", "informational"), 5
        )
    )):
        sev = f.get("severity", "informational")
        t.add_row(
            f["id"][:8],
            f"[{severity_style(sev)}]{sev}[/]",
            f.get("title", "")[:45],
            f.get("vuln_class", ""),
            f.get("url", "")[:40],
            f.get("status", ""),
        )
    console.print(t)
    console.print(f"[dim]{len(findings)} finding(s)[/dim]")


@findings_group.command("show")
@click.argument("finding_id")
def show_cmd(finding_id):
    """Show full detail for a finding."""
    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    f = repo._row_to_dict(dict(rows[0]))
    sev = f.get("severity", "informational")

    content = f"""**Title:** {f.get('title')}
**Severity:** {sev.upper()}
**Status:** {f.get('status')}
**Vuln Class:** {f.get('vuln_class')}
**URL:** {f.get('url')}
**Parameter:** {f.get('parameter') or '—'}

**Description:**
{f.get('description') or '*(not set)*'}

**Impact:**
{f.get('impact') or '*(not set)*'}

**Remediation:**
{f.get('remediation') or '*(not set)*'}
"""
    steps = f.get("reproduction_steps_json") or f.get("reproduction_steps") or []
    if isinstance(steps, str):
        steps = json.loads(steps)
    if steps:
        content += "\n**Reproduction Steps:**\n"
        for i, step in enumerate(steps, 1):
            content += f"{i}. {step}\n"

    cvss_data = f.get("cvss_json") or f.get("cvss")
    if isinstance(cvss_data, str):
        cvss_data = json.loads(cvss_data) if cvss_data and cvss_data != "null" else None
    if cvss_data and cvss_data.get("score"):
        content += f"\n**CVSS:** {cvss_data['score']} — {cvss_data.get('vector_string', '')}"

    from rich.markdown import Markdown
    console.print(Panel(Markdown(content), title=f"[{severity_style(sev)}]{f['id'][:8]}[/]"))


@findings_group.command("status")
@click.argument("finding_id")
@click.argument("status", type=click.Choice([s.value for s in FindingStatus]))
def status_cmd(finding_id, status):
    """Update finding status."""
    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    repo.update_status(rows[0]["id"], status)
    success(f"Finding {rows[0]['id'][:8]} status → {status}")


@findings_group.command("cvss")
@click.argument("finding_id")
def cvss_cmd(finding_id):
    """Interactive CVSS 3.1 calculator for a finding."""
    from .cvss import interactive_cvss, score_to_severity

    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    cvss = interactive_cvss()
    console.print(f"\n[bold]CVSS Score:[/bold] {cvss.score} ({score_to_severity(cvss.score).upper()})")
    console.print(f"[dim]{cvss.vector_string}[/dim]")

    if click.confirm("Save this CVSS to the finding?"):
        repo.update_fields(rows[0]["id"],
                           cvss_json=json.dumps(cvss.model_dump()),
                           severity=score_to_severity(cvss.score))
        success("CVSS saved.")


@findings_group.command("enrich")
@click.argument("finding_id")
def enrich_cmd(finding_id):
    """Use AI to draft description, impact, reproduction steps, and remediation."""
    from ...modules.ai.client import AIClient
    from rich.live import Live
    from rich.markdown import Markdown

    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    finding_dict = repo._row_to_dict(dict(rows[0]))

    try:
        client = AIClient()
    except RuntimeError as e:
        error(str(e))
        raise SystemExit(1)

    info("Enriching finding with AI...")
    result = client.enrich_finding(finding_dict, config.db_path(ws))

    if result:
        updates: dict = {}
        if result.get("description"):
            updates["description"] = result["description"]
        if result.get("impact"):
            updates["impact"] = result["impact"]
        if result.get("reproduction_steps"):
            updates["reproduction_steps_json"] = json.dumps(result["reproduction_steps"])
        if result.get("remediation"):
            updates["remediation"] = result["remediation"]
        if result.get("references"):
            updates["references_json"] = json.dumps(result["references"])
        updates["ai_generated"] = 1

        if updates:
            repo.update_fields(rows[0]["id"], **updates)
            success("Finding enriched. Review with [bold]mewtwo findings show " + finding_id[:8] + "[/bold]")
    else:
        error("AI returned no enrichment.")


@findings_group.command("attach")
@click.argument("finding_id")
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--kind", type=click.Choice(["screenshot", "burp", "poc", "note", "request", "response"]),
              default="note", help="Type of evidence")
@click.option("--caption", default="", help="Short description of this attachment")
def attach_cmd(finding_id, filepath, kind, caption):
    """Attach a file (screenshot, Burp export, PoC script) to a finding.

    The file is copied into the evidence directory and linked in the finding record.

    \b
    Examples:
      mewtwo findings attach abc123 screenshot.png --kind screenshot --caption "XSS PoC"
      mewtwo findings attach abc123 burp_export.xml --kind burp
      mewtwo findings attach abc123 exploit.py --kind poc
    """
    import shutil
    from pathlib import Path as P

    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    fid = rows[0]["id"]
    src = P(filepath)

    # Copy file into evidence/<finding_id>/attachments/
    dest_dir = config.evidence_dir(ws) / fid / "attachments"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(src, dest)

    # Record in DB evidence JSON
    existing_evidence = json.loads(rows[0].get("evidence_json") or "[]")
    existing_evidence.append({
        "kind": kind,
        "content": str(dest),
        "caption": caption or src.name,
    })
    repo.update_fields(fid, evidence_json=json.dumps(existing_evidence))
    success(f"[{kind}] {src.name} attached to finding {fid[:8]}.")
    console.print(f"  Stored at: [dim]{dest}[/dim]")


@findings_group.command("evidence")
@click.argument("finding_id")
@click.option("--http", "show_http", is_flag=True, help="Show raw HTTP captures")
@click.option("--attachments", "show_attach", is_flag=True, help="List file attachments")
def evidence_cmd(finding_id, show_http, show_attach):
    """Show all evidence for a finding (HTTP captures + file attachments).

    By default shows both. Use --http or --attachments to filter.
    """
    from pathlib import Path as P
    from rich.syntax import Syntax
    from rich.table import Table

    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    fid = rows[0]["id"]
    show_all = not show_http and not show_attach

    # 1. HTTP captures (auto-saved .txt files)
    if show_http or show_all:
        ev_base = config.evidence_dir(ws)
        # Match by full ID or prefix
        candidates = [ev_base / fid] + list(ev_base.glob(f"{finding_id}*"))
        ev_dir = next((c for c in candidates if c.is_dir()), None)

        http_files = sorted(ev_dir.glob("*.txt")) if ev_dir else []
        if http_files:
            console.print(f"\n[bold]HTTP Captures ({len(http_files)})[/bold]")
            for fp in http_files:
                console.print(f"\n[dim]{fp.name}[/dim]")
                console.print(Syntax(fp.read_text()[:3000], "http", theme="monokai", line_numbers=False))
        elif show_http:
            info("No HTTP capture files found.")

    # 2. File attachments
    if show_attach or show_all:
        evidence_list = json.loads(rows[0].get("evidence_json") or "[]")
        file_attachments = [e for e in evidence_list if P(e.get("content", "")).exists()]

        if file_attachments:
            t = Table("Kind", "File", "Caption", title="File Attachments")
            for e in file_attachments:
                p = P(e["content"])
                t.add_row(e.get("kind", "—"), p.name, e.get("caption", ""))
            console.print(t)
        elif show_attach:
            info("No file attachments found. Use [bold]mewtwo findings attach[/bold] to add one.")

    # 3. Inline evidence notes
    if show_all:
        evidence_list = json.loads(rows[0].get("evidence_json") or "[]")
        notes = [e for e in evidence_list if not P(e.get("content", "NOEXIST")).exists()]
        if notes:
            console.print(f"\n[bold]Inline Evidence Notes ({len(notes)})[/bold]")
            for e in notes:
                console.print(f"\n[dim]{e.get('kind', 'note')}[/dim]: {e.get('caption', '')}")
                console.print(e.get("content", "")[:500])


@findings_group.command("delete")
@click.argument("finding_id")
@click.confirmation_option(prompt="Are you sure you want to delete this finding?")
def delete_cmd(finding_id):
    """Delete a finding."""
    ws, db, target_row, repo = _get_repo()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    repo.delete(rows[0]["id"])
    success(f"Finding {rows[0]['id'][:8]} deleted.")
