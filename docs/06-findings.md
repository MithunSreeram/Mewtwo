# Mewtwo — Findings Module

The findings module lives in `mewtwo/modules/findings/` and handles everything
after a vulnerability is discovered: CVSS scoring, status tracking, evidence
management, and AI enrichment.

---

## cvss.py — Implementing CVSS 3.1

CVSS (Common Vulnerability Scoring System) is the industry standard for measuring
vulnerability severity. The score comes from eight metric values multiplied together
through a specific formula.

### Metric weights

```python
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                           # Attack Complexity
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}     # Privileges Required (scope unchanged)
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}     # Privileges Required (scope changed)
_UI = {"N": 0.85, "R": 0.62}                           # User Interaction
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}              # Confidentiality / Integrity / Availability
```

These are the exact weights from the CVSS 3.1 specification. `_PR` has two tables
because when `Scope = Changed`, a low-privileged attacker crossing a security boundary
is weighted more heavily than when the scope stays within the same component.

### Score calculation

```python
def calculate_cvss(v: CVSSVector) -> CVSSVector:
    # Privileges Required depends on scope
    pr = _PR_CHANGED.get(v.privileges_required) if v.scope == "C" \
         else _PR_UNCHANGED.get(v.privileges_required)

    # Impact Sub-Score (ISS)
    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    # Impact
    if s == "U":  # Scope Unchanged
        impact = 6.42 * iss
    else:         # Scope Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    else:
        if s == "U":
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)  # scope multiplier
        score = round(raw * 10) / 10  # round up to 1 decimal
```

The `round(raw * 10) / 10` is the CVSS 3.1 "round up" operation — it rounds
to the nearest 0.1, always towards higher values.

If `impact <= 0`, the score is always 0 regardless of exploitability. A zero-impact
vuln isn't a vulnerability.

### Score → severity mapping

```python
def score_to_severity(score: float) -> str:
    if score >= 9.0:  return "critical"
    elif score >= 7.0: return "high"
    elif score >= 4.0: return "medium"
    elif score > 0:    return "low"
    return "informational"
```

This maps the float score to the five severity labels used everywhere in Mewtwo.
The thresholds (9.0, 7.0, 4.0) match the official CVSS 3.1 severity ranges.

### Interactive calculator

```python
def interactive_cvss() -> CVSSVector:
    av = click.prompt("Attack Vector (N=Network A=Adjacent L=Local P=Physical)",
                      type=click.Choice(["N", "A", "L", "P"]), default="N")
    ...
    raw = CVSSVector(attack_vector=av, ...)
    return calculate_cvss(raw)
```

`click.Choice` enforces valid inputs — you can't accidentally type `"network"` instead
of `"N"`. The function returns a completed `CVSSVector` with `score` and
`vector_string` populated, ready to save to a finding.

---

## storage/findings.py — FindingRepository

### Upsert

```python
def upsert(self, finding: Finding) -> None:
    self.db["findings"].upsert({
        "id": finding.id,
        "severity": finding.severity.value,      # Enum → string
        "status": finding.status.value,
        "cvss_json": json.dumps(finding.cvss.model_dump() if finding.cvss else None),
        "reproduction_steps_json": json.dumps(finding.reproduction_steps),
        "evidence_json": json.dumps([e.model_dump() for e in finding.evidence]),
        ...
    }, pk="id")
```

JSON columns use the `_json` suffix convention: `evidence_json`, `cvss_json`,
`reproduction_steps_json`, `references_json`, `tags_json`. The `BaseRepository`
`_deserialize_row` method uses this suffix to know which columns to `json.loads()`
when reading back.

### Filtered queries

```python
def for_target(self, target_id, severity=None, status=None) -> list[dict]:
    where = "target_id = ?"
    params = [target_id]
    if severity:
        where += " AND severity = ?"
        params.append(severity)
    if status:
        where += " AND status = ?"
        params.append(status)
    return [self._row_to_dict(dict(r))
            for r in self.db["findings"].rows_where(where, params)]
```

The `rows_where` method from `sqlite-utils` accepts raw SQL fragments — this lets
filters stack without string concatenation bugs. `params` is always a list so
sqlite3 handles escaping — no SQL injection.

### Partial updates

```python
def update_fields(self, finding_id: str, **fields) -> None:
    fields["updated_at"] = datetime.utcnow().isoformat()
    self.db["findings"].update(finding_id, fields)
```

`**fields` makes this generic — `repo.update_fields(id, description="...", impact="...")`
updates only those columns. It always stamps `updated_at` so the history is accurate.

---

## cli.py — Findings Commands

### `mewtwo findings add`

```python
@findings_group.command("add")
@click.option("--title", prompt=True)
@click.option("--url", prompt=True)
@click.option("--vuln-class", prompt=True)
@click.option("--severity", prompt=True,
              type=click.Choice([s.value for s in Severity]))
```

`prompt=True` means if you don't pass the flag on the command line, click prompts
interactively. `click.Choice([s.value for s in Severity])` builds the valid options
from the enum at runtime — so `["critical","high","medium","low","informational"]`.
If you add a new `Severity` value, the CLI automatically accepts it.

### `mewtwo findings list`

```python
findings = repo.for_target(target_row["id"], severity=severity, status=status)

for f in sorted(findings, key=lambda x: (
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(
        x.get("severity", "informational"), 5
    )
)):
```

Results are sorted by severity (critical first) using a priority dict. The `.get(..., 5)`
puts unknown severities at the end rather than crashing.

The severity column is Rich-formatted:
```python
sev = f.get("severity", "informational")
f"[{severity_style(sev)}]{sev}[/]"
# → "[bold red]critical[/bold red]" etc.
```

### `mewtwo findings show`

```python
rows = list(db["findings"].rows_where(
    "id LIKE ? AND target_id = ?", [f"{finding_id}%", target_row["id"]]
))
```

`id LIKE ?` with a `%` suffix means you can type just the first 8 characters of
the UUID instead of the full 36-character ID. The `AND target_id = ?` prevents
one workspace's IDs matching another workspace's findings.

The full detail is rendered as a Markdown `Panel`:
```python
from rich.markdown import Markdown
console.print(Panel(Markdown(content), title=f"[{severity_style(sev)}]{f['id'][:8]}[/]"))
```

### `mewtwo findings cvss`

```python
cvss = interactive_cvss()
console.print(f"\n[bold]CVSS Score:[/bold] {cvss.score} ({score_to_severity(cvss.score).upper()})")

if click.confirm("Save this CVSS to the finding?"):
    repo.update_fields(rows[0]["id"],
                       cvss_json=json.dumps(cvss.model_dump()),
                       severity=score_to_severity(cvss.score))
```

Saves both the full CVSS vector (all 8 metrics + score + vector string) and updates
the top-level `severity` field — so `mewtwo findings list` reflects the CVSS-derived
severity automatically.

### `mewtwo findings enrich`

```python
result = client.enrich_finding(finding_dict, config.db_path(ws))

if result:
    updates = {}
    if result.get("description"):   updates["description"] = result["description"]
    if result.get("impact"):        updates["impact"] = result["impact"]
    if result.get("reproduction_steps"):
        updates["reproduction_steps_json"] = json.dumps(result["reproduction_steps"])
    ...
    updates["ai_generated"] = 1
    repo.update_fields(rows[0]["id"], **updates)
```

The AI result fields are optional-checked before saving — if Claude didn't return
a `remediation`, the existing value isn't overwritten with `None`.
`ai_generated = 1` is a flag you can filter on to distinguish AI-drafted content
from manually written notes.

### `mewtwo findings attach`

```python
dest_dir = config.evidence_dir(ws) / fid / "attachments"
dest_dir.mkdir(parents=True, exist_ok=True)
dest = dest_dir / src.name
shutil.copy2(src, dest)   # preserves timestamps

existing_evidence = json.loads(rows[0].get("evidence_json") or "[]")
existing_evidence.append({
    "kind": kind,         # screenshot | burp | poc | note | request | response
    "content": str(dest), # absolute path
    "caption": caption or src.name,
})
repo.update_fields(fid, evidence_json=json.dumps(existing_evidence))
```

The file is copied into the workspace's `evidence/<finding_id>/attachments/` directory.
The DB stores the absolute path in `content` — the `evidence` command checks
`Path(e["content"]).exists()` to distinguish file attachments from inline text notes.

### `mewtwo findings evidence`

```python
# 1. HTTP captures (auto-saved .txt files from hunt runner)
ev_dir = config.evidence_dir(ws) / fid     # or prefix match
http_files = sorted(ev_dir.glob("*.txt"))
console.print(Syntax(fp.read_text()[:3000], "http", ...))

# 2. File attachments (stored in DB evidence_json)
evidence_list = json.loads(rows[0].get("evidence_json") or "[]")
file_attachments = [e for e in evidence_list if Path(e.get("content", "")).exists()]

# 3. Inline notes (evidence_json entries where content is text, not a path)
notes = [e for e in evidence_list if not Path(e.get("content", "NOEXIST")).exists()]
```

The evidence command consolidates three evidence sources:
1. `.txt` files auto-created by the hunt runner (raw HTTP request/response)
2. Files manually attached with `mewtwo findings attach`
3. Inline text notes stored in `evidence_json`

The `show_all = not show_http and not show_attach` pattern means the default
(no flags) shows everything, while `--http` or `--attachments` filters to one type.
