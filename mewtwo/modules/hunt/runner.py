"""Hunt runner — dispatches checks against attack vectors."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from ...db import get_db
from ...models.finding import Finding, Severity, FindingStatus, Evidence
from ...models.surface import AttackVector, VectorCategory
from ...storage.findings import FindingRepository
from ...storage.surface import SurfaceRepository
from ...utils.console import console, info, success, warn
from .checks import ALL_CHECKS
from .checks.base import BaseCheck, FindingDraft


async def run_hunt(
    target_id: str,
    db_path: Path,
    evidence_dir: Path | None = None,
    category_filter: str | None = None,
    vector_id: str | None = None,
    check_names: list[str] | None = None,
    use_ai: bool = True,
) -> list[Finding]:
    """Run hunt checks against attack vectors. Returns confirmed/draft findings."""
    db = get_db(db_path)
    surf = SurfaceRepository(db)
    findings_repo = FindingRepository(db)

    # Select vectors
    if vector_id:
        rows = list(db["attack_vectors"].rows_where(
            "id LIKE ? AND target_id = ?", [f"{vector_id}%", target_id]
        ))
    else:
        rows = surf.for_target(target_id, category=category_filter)

    # Only unchecked vectors by default
    unchecked = [r for r in rows if not r.get("checked")]
    if not unchecked:
        info("All attack vectors have been checked. Use --vector-id to re-run a specific one.")
        return []

    info(f"Hunting {len(unchecked)} unchecked vector(s)...")

    # Select checks
    checks_to_run: list[type[BaseCheck]] = ALL_CHECKS
    if check_names:
        checks_to_run = [c for c in ALL_CHECKS if c.name in check_names]

    ai = None
    if use_ai:
        try:
            from ...modules.ai.client import AIClient
            ai = AIClient()
        except Exception as e:
            warn(f"AI disabled: {e}")

    all_findings: list[Finding] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0"},
    ) as http:
        for vector_row in unchecked:
            vector = AttackVector(
                id=vector_row["id"],
                target_id=vector_row["target_id"],
                category=VectorCategory(vector_row["category"]),
                title=vector_row["title"],
                description=vector_row.get("description", ""),
                url=vector_row["url"],
                parameters=vector_row.get("parameters", []),
                risk_rating=vector_row.get("risk_rating", "medium"),
            )

            console.print(f"\n[dim]Vector:[/dim] {vector.title[:60]}")

            # Find applicable checks
            applicable = [
                c for c in checks_to_run
                if not c.applicable_categories or
                   vector.category.value in c.applicable_categories
            ]

            vector_findings: list[Finding] = []
            for check_cls in applicable:
                check = check_cls()
                try:
                    drafts = await check.run(vector, http, ai)
                    for draft in drafts:
                        finding = _draft_to_finding(draft, target_id)
                        # Save raw HTTP evidence to disk if captured
                        if evidence_dir and (draft.raw_request or draft.raw_response):
                            from ...utils.evidence import save_evidence
                            ev_path = save_evidence(
                                evidence_dir=evidence_dir,
                                finding_id=finding.id,
                                label=check.name,
                                raw_request=draft.raw_request,
                                raw_response=draft.raw_response,
                            )
                            # Attach file path as an evidence entry
                            from ...models.finding import Evidence
                            finding.evidence.append(
                                Evidence(kind="note", content=f"Evidence file: {ev_path}")
                            )
                        findings_repo.upsert(finding)
                        vector_findings.append(finding)
                        console.print(
                            f"  [yellow]→ {draft.severity.upper()}[/yellow] {draft.title[:60]}"
                        )
                except Exception as e:
                    warn(f"  Check {check.name} failed: {e}")

            surf.mark_checked(vector.id)
            all_findings.extend(vector_findings)

            if not vector_findings:
                console.print(f"  [dim]No findings[/dim]")

    success(f"Hunt complete: {len(all_findings)} finding(s) across {len(unchecked)} vector(s)")
    return all_findings


def _draft_to_finding(draft: FindingDraft, target_id: str) -> Finding:
    return Finding(
        target_id=target_id,
        title=draft.title,
        vuln_class=draft.vuln_class,
        severity=Severity(draft.severity),
        status=FindingStatus.DRAFT,
        url=draft.url,
        parameter=draft.parameter,
        description=draft.description,
        evidence=[Evidence(kind="note", content=draft.evidence)] if draft.evidence else [],
        references=draft.references,
    )
