"""Nuclei integration — run the nuclei scanner and import results as findings.

Nuclei ships thousands of community templates (CVEs, misconfigs, exposures). Rather than
reimplement them, Mewtwo shells out to a locally installed ``nuclei`` binary, parses its
JSONL output, and folds each result into the findings store with mapped severity. Degrades
gracefully with an install hint when the binary is absent.
"""

from __future__ import annotations

import json

from ...models.finding import Finding, Severity, FindingStatus, Evidence
from ...utils.console import info, success, warn
from ...utils.process import run, tool_available

# nuclei severity strings → Mewtwo Severity
_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
}


def nuclei_available() -> bool:
    return tool_available("nuclei")


def _result_to_finding(target_id: str, result: dict) -> Finding:
    info_block = result.get("info", {})
    severity = _SEV_MAP.get(str(info_block.get("severity", "info")).lower(), Severity.INFORMATIONAL)
    template_id = result.get("template-id", result.get("templateID", "nuclei"))
    matched = result.get("matched-at", result.get("host", ""))
    name = info_block.get("name", template_id)

    refs = info_block.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]

    return Finding(
        target_id=target_id,
        title=f"[nuclei] {name}",
        vuln_class=template_id,
        severity=severity,
        status=FindingStatus.DRAFT,
        url=matched,
        description=(
            f"{info_block.get('description', '').strip()}\n\n"
            f"Detected by nuclei template `{template_id}`."
        ).strip(),
        evidence=[Evidence(
            kind="note",
            content=json.dumps(result, indent=2)[:4000],
            caption=f"nuclei match: {template_id}",
        )],
        references=[r for r in refs if isinstance(r, str)],
        tags=["nuclei", template_id],
    )


async def run_nuclei(
    target_id: str,
    targets: list[str],
    severities: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 1800,
) -> list[Finding]:
    """Run nuclei against a list of URLs/hosts. Returns parsed Findings."""
    if not nuclei_available():
        warn("nuclei not found on PATH. Install from https://github.com/projectdiscovery/nuclei")
        return []
    if not targets:
        info("No alive targets to scan with nuclei.")
        return []

    # Feed targets via stdin-style args; nuclei accepts repeated -target.
    cmd = ["nuclei", "-jsonl", "-silent", "-duc"]  # -duc: disable update check
    for t in targets:
        cmd += ["-target", t]
    if severities:
        cmd += ["-severity", severities]
    if extra_args:
        cmd += extra_args

    info(f"Running nuclei against {len(targets)} target(s)...")
    try:
        rc, stdout, stderr = await run(*cmd, timeout=timeout)
    except TimeoutError:
        warn(f"nuclei timed out after {timeout}s")
        return []

    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(_result_to_finding(target_id, result))

    success(f"nuclei: {len(findings)} result(s)")
    return findings
