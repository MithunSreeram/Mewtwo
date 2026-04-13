"""Report builder — assembles context from DB, enriches with AI, renders."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from ...db import get_db
from ...models.finding import Finding, Severity, FindingStatus, CVSSVector, Evidence
from ...storage.findings import FindingRepository
from ...utils.console import info, success


def _deserialize_finding(row: dict) -> Finding:
    """Convert a raw DB row dict to a Finding model."""
    cvss_raw = row.get("cvss_json") or row.get("cvss")
    cvss = None
    if cvss_raw and cvss_raw != "null":
        if isinstance(cvss_raw, str):
            cvss_raw = json.loads(cvss_raw)
        if cvss_raw:
            cvss = CVSSVector(**cvss_raw)

    steps_raw = row.get("reproduction_steps_json") or row.get("reproduction_steps") or "[]"
    steps = json.loads(steps_raw) if isinstance(steps_raw, str) else steps_raw

    ev_raw = row.get("evidence_json") or row.get("evidence") or "[]"
    ev_list = json.loads(ev_raw) if isinstance(ev_raw, str) else ev_raw
    evidence = [Evidence(**e) for e in ev_list if isinstance(e, dict)]

    refs_raw = row.get("references_json") or row.get("references") or "[]"
    references = json.loads(refs_raw) if isinstance(refs_raw, str) else refs_raw

    return Finding(
        id=row["id"],
        target_id=row["target_id"],
        title=row.get("title", ""),
        vuln_class=row.get("vuln_class", ""),
        severity=Severity(row.get("severity", "informational")),
        status=FindingStatus(row.get("status", "draft")),
        cvss=cvss,
        url=row.get("url", ""),
        parameter=row.get("parameter", ""),
        description=row.get("description", ""),
        impact=row.get("impact", ""),
        reproduction_steps=steps,
        evidence=evidence,
        remediation=row.get("remediation", ""),
        references=references,
        ai_generated=bool(row.get("ai_generated", 0)),
    )


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def build_report_context(
    db_path: Path,
    include_statuses: list[str] | None = None,
    use_ai: bool = True,
) -> dict:
    """Build the full template context dict for report rendering."""
    if include_statuses is None:
        include_statuses = ["confirmed", "reported", "accepted"]

    db = get_db(db_path)
    target_rows = list(db["targets"].rows)
    if not target_rows:
        raise RuntimeError("No target found in workspace.")

    target_row = target_rows[0]
    repo = FindingRepository(db)

    all_findings_rows = repo.for_target(target_row["id"])
    filtered = [
        f for f in all_findings_rows
        if f.get("status") in include_statuses
    ]

    findings = [_deserialize_finding(f) for f in filtered]
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 9))

    # AI enrichment for findings with missing narrative
    if use_ai:
        try:
            from ...modules.ai.client import AIClient
            client = AIClient()
            for finding in findings:
                if not finding.description or not finding.impact:
                    info(f"Enriching: {finding.title[:50]}...")
                    result = client.enrich_finding(
                        finding.model_dump(mode="json"), db_path
                    )
                    if result:
                        if result.get("description"):
                            finding.description = result["description"]
                        if result.get("impact"):
                            finding.impact = result["impact"]
                        if result.get("reproduction_steps"):
                            finding.reproduction_steps = result["reproduction_steps"]
                        if result.get("remediation"):
                            finding.remediation = result["remediation"]
                        finding.ai_generated = True
        except Exception as e:
            info(f"AI enrichment skipped: {e}")

    # Executive summary
    exec_summary = ""
    if use_ai and findings:
        try:
            from ...modules.ai.client import AIClient
            client = AIClient()
            info("Generating executive summary...")
            findings_data = [
                {"title": f.title, "severity": f.severity.value, "impact": f.impact}
                for f in findings
            ]
            exec_summary = client.write_executive_summary(target_row["name"], findings_data)
        except Exception:
            exec_summary = _default_exec_summary(target_row["name"], findings)
    else:
        exec_summary = _default_exec_summary(target_row["name"], findings)

    class TargetStub:
        name = target_row["name"]
        platform = target_row.get("platform", "")
        program_url = target_row.get("program_url", "")

    # Convert findings to plain dicts for Jinja2
    findings_dicts = []
    for f in findings:
        d = f.model_dump(mode="json")
        if d.get("cvss") and not isinstance(d["cvss"], dict):
            d["cvss"] = None
        findings_dicts.append(d)

    return {
        "target": TargetStub(),
        "findings": findings_dicts,
        "executive_summary": exec_summary,
        "report_date": date.today().isoformat(),
    }


def _default_exec_summary(target_name: str, findings: list[Finding]) -> str:
    from collections import Counter
    counts = Counter(f.severity.value for f in findings)
    parts = []
    for sev in ("critical", "high", "medium", "low", "informational"):
        if counts.get(sev, 0) > 0:
            parts.append(f"{counts[sev]} {sev}")
    return (
        f"This assessment of {target_name} identified {len(findings)} vulnerability(-ies): "
        + ", ".join(parts) + ". "
        "Findings should be prioritized by severity for remediation."
    )
