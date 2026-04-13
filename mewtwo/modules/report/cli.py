"""mewtwo report — report generation commands."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import click
from rich.markdown import Markdown

from ... import config
from ...db import get_db
from ...storage.findings import FindingRepository
from ...utils.console import console, error, info, success


def _get_workspace_and_db():
    ws = config.require_active_workspace()
    db = get_db(config.db_path(ws))
    targets = list(db["targets"].rows)
    if not targets:
        error("No target in workspace.")
        raise SystemExit(1)
    return ws, db, targets[0]


@click.group("report")
def report_group():
    """Report generation — produce professional BB submission reports."""


@report_group.command("generate")
@click.option("--format", "fmt", type=click.Choice(["md", "html", "all"]), default="all")
@click.option("--output", "-o", help="Output path (without extension)")
@click.option("--include", "include_status",
              type=click.Choice(["draft", "confirmed", "all"]), default="confirmed")
@click.option("--no-ai", is_flag=True)
def generate_cmd(fmt, output, include_status, no_ai):
    """Generate a full report from confirmed findings."""
    from .builder import build_report_context
    from .renderer import render_markdown, render_html

    ws, db, target_row = _get_workspace_and_db()

    if include_status == "all":
        statuses = ["draft", "confirmed", "reported", "accepted"]
    elif include_status == "draft":
        statuses = ["draft", "confirmed", "reported", "accepted"]
    else:
        statuses = ["confirmed", "reported", "accepted"]

    info("Building report context...")
    try:
        ctx = build_report_context(
            db_path=config.db_path(ws),
            include_statuses=statuses,
            use_ai=not no_ai,
        )
    except RuntimeError as e:
        error(str(e))
        raise SystemExit(1)

    if not ctx["findings"]:
        info("No findings match the filter. Try --include all.")
        return

    reports_dir = config.reports_dir(ws)
    slug = target_row["slug"]
    today = date.today().isoformat()
    base_name = output or str(reports_dir / f"{slug}_{today}")

    if fmt in ("md", "all"):
        md_path = Path(f"{base_name}.md")
        md_path.write_text(render_markdown(ctx))
        success(f"Markdown report: {md_path}")

    if fmt in ("html", "all"):
        html_path = Path(f"{base_name}.html")
        html_path.write_text(render_html(ctx))
        success(f"HTML report: {html_path}")


@report_group.command("preview")
def preview_cmd():
    """Quick terminal preview of confirmed findings."""
    ws, db, target_row = _get_workspace_and_db()
    repo = FindingRepository(db)
    findings = repo.for_target(target_row["id"])

    if not findings:
        info("No findings to preview.")
        return

    lines = [f"# {target_row['name']} — Findings Preview\n"]
    for f in findings:
        sev = f.get("severity", "informational").upper()
        lines.append(f"## [{sev}] {f.get('title')}")
        lines.append(f"**URL:** `{f.get('url')}`")
        if f.get("description"):
            lines.append(f"\n{f['description'][:300]}...")
        lines.append("")

    console.print(Markdown("\n".join(lines)))


@report_group.command("export")
@click.argument("finding_id")
@click.option("--format", "fmt", type=click.Choice(["md", "html"]), default="md")
@click.option("--output", "-o")
def export_cmd(finding_id, fmt, output):
    """Export a single finding as a standalone report for submission."""
    from .builder import _deserialize_finding
    from .renderer import render_markdown, render_html
    from datetime import date

    ws, db, target_row = _get_workspace_and_db()

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    repo = FindingRepository(db)
    f = _deserialize_finding(repo._row_to_dict(dict(rows[0])))

    class TargetStub:
        name = target_row["name"]
        platform = target_row.get("platform", "")
        program_url = target_row.get("program_url", "")

    ctx = {
        "target": TargetStub(),
        "findings": [f.model_dump(mode="json")],
        "executive_summary": f.impact or f.description or "",
        "report_date": date.today().isoformat(),
    }

    out_path = Path(output) if output else (
        config.reports_dir(ws) / f"finding_{f.id[:8]}_{date.today().isoformat()}.{fmt}"
    )

    if fmt == "md":
        out_path.write_text(render_markdown(ctx))
    else:
        out_path.write_text(render_html(ctx))

    success(f"Finding exported: {out_path}")


@report_group.command("submit")
@click.argument("finding_id")
@click.option("--platform", required=True,
              type=click.Choice(["hackerone", "bugcrowd", "h1", "bc"]),
              help="Target platform")
@click.option("--h1-username", envvar="H1_USERNAME")
@click.option("--h1-token", envvar="H1_API_TOKEN")
@click.option("--h1-program", envvar="H1_PROGRAM_HANDLE")
@click.option("--bc-token", envvar="BC_API_TOKEN")
@click.option("--bc-program", envvar="BC_PROGRAM_CODE")
@click.option("--dry-run", is_flag=True, help="Preview report body without submitting")
def submit_cmd(finding_id, platform, h1_username, h1_token, h1_program,
               bc_token, bc_program, dry_run):
    """Submit a confirmed finding directly to HackerOne or Bugcrowd."""
    from .submit import HackerOneClient, BugcrowdClient, _build_h1_report_body
    from .builder import _deserialize_finding

    ws, db, target_row = _get_workspace_and_db()
    repo = FindingRepository(db)

    rows = list(db["findings"].rows_where(
        "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
    ))
    if not rows:
        error(f"Finding not found: {finding_id}")
        raise SystemExit(1)

    f = _deserialize_finding(repo._row_to_dict(dict(rows[0])))
    finding_dict = f.model_dump(mode="json")

    if dry_run:
        console.print("[info]Dry run — report body preview:[/info]\n")
        console.print(_build_h1_report_body(finding_dict))
        return

    platform = platform.lower()

    if platform in ("hackerone", "h1"):
        if not all([h1_username, h1_token, h1_program]):
            error("HackerOne requires --h1-username, --h1-token, --h1-program (or env vars H1_USERNAME, H1_API_TOKEN, H1_PROGRAM_HANDLE)")
            raise SystemExit(1)
        client = HackerOneClient(h1_username, h1_token, h1_program)
        result = client.submit(finding_dict)

    elif platform in ("bugcrowd", "bc"):
        if not all([bc_token, bc_program]):
            error("Bugcrowd requires --bc-token, --bc-program (or env vars BC_API_TOKEN, BC_PROGRAM_CODE)")
            raise SystemExit(1)
        client = BugcrowdClient(bc_token, bc_program)
        result = client.submit(finding_dict)

    else:
        error(f"Unknown platform: {platform}")
        raise SystemExit(1)

    if "error" not in result:
        # Mark finding as reported
        repo.update_status(f.id, "reported")
        success(f"Finding status updated to 'reported'.")
