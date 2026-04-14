# Mewtwo — Report Module

The report module lives in `mewtwo/modules/report/`. It reads findings from the
DB, optionally enriches them with AI, and renders to Markdown, HTML, or PDF.
It also handles platform submission to HackerOne and Bugcrowd.

---

## renderer.py — Jinja2 + WeasyPrint

### Template resolution

```python
def _resolve_template(name: str) -> tuple[Environment, str]:
    user_dir = _user_templates_dir()        # ~/.mewtwo/templates/
    if (user_dir / name).exists():
        return _get_env(user_dir), name     # user override wins
    return _get_env(_bundled_templates_dir()), name  # fall back to bundled
```

Mewtwo ships default templates. If you put a `report.html.j2` in
`~/.mewtwo/templates/`, that file takes precedence. This lets you customise the
report layout per engagement without touching the package source.

`_bundled_templates_dir()` is `Path(__file__).parent / "templates"` — always
points to the templates next to `renderer.py`, regardless of where the command
is run from.

### HTML rendering

```python
def _get_env(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
```

`autoescape=select_autoescape(["html"])` turns on HTML escaping automatically for
`.html` template files. Finding titles and descriptions could contain `<script>`
tags (they came from XSS testing), so autoescaping is not optional.

### PDF rendering

```python
def render_pdf(context: dict, output_path: Path) -> Path:
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        raise ImportError("pip install 'mewtwo[pdf]'...")

    html_content = render_html(context)

    print_css = CSS(string="""
        @page { margin: 2cm; size: A4; }
        body { font-family: 'DejaVu Sans'; font-size: 11pt; }
        .finding-card { page-break-inside: avoid; border: 1px solid #ddd; }
        h1, h2, h3 { page-break-after: avoid; }
        .severity-critical { color: #c0392b; }
        .severity-high     { color: #e67e22; }
    """)

    HTML(string=html_content).write_pdf(
        str(output_path),
        stylesheets=[print_css],
        presentational_hints=True,
    )
```

`render_pdf` first renders the full HTML string, then converts it. The `print_css`
applies on top of the existing HTML template styles:

- `page-break-inside: avoid` on `.finding-card` keeps each finding on one page
- `page-break-after: avoid` on headings prevents orphan headers
- `presentational_hints=True` tells WeasyPrint to honour HTML `width`, `height`,
  and `align` attributes — needed for tables with explicit widths

WeasyPrint needs system libraries (`libpango-1.0-0`) — that's why it's an optional
dependency in `pyproject.toml` under `[pdf]`.

---

## builder.py — Report Context Assembly

The builder reads all findings for a target, groups them by severity, calls AI
for the executive summary (optional), and returns the template context dict.

```python
def build_report_context(target, findings, ai_summary=None) -> dict:
    severity_order = ["critical", "high", "medium", "low", "informational"]
    grouped = {s: [] for s in severity_order}
    for f in findings:
        grouped[f.get("severity", "informational")].append(f)

    stats = {
        "total": len(findings),
        "critical": len(grouped["critical"]),
        "high": len(grouped["high"]),
        ...
    }

    return {
        "target": target,
        "findings": findings,
        "findings_by_severity": grouped,
        "stats": stats,
        "generated_at": datetime.utcnow().isoformat(),
        "executive_summary": ai_summary or "",
    }
```

The `findings_by_severity` dict is pre-grouped so the Jinja2 template can iterate
severity buckets without calling `filter()` inside the template.

---

## submit.py — Platform Submission

### HackerOne

HackerOne uses HTTP Basic Auth (username + API token):

```python
class HackerOneClient:
    def __init__(self, username, api_token, program_handle):
        self.auth = (username, api_token)   # → httpx auth tuple
        self.program = program_handle
```

The submission payload follows the HackerOne v1 JSON:API format:

```python
payload = {
    "data": {
        "type": "report",
        "attributes": {
            "title": title,
            "vulnerability_information": description,   # markdown body
            "severity_rating": severity,                # "high", "medium", etc.
            "impact": finding.get("impact", ""),
        },
        "relationships": {
            "severity": {
                "data": {"type": "severity", "attributes": {"rating": severity}}
            }
        }
    }
}

resp = client.post(f"{_H1_API}/reports", json=payload, params={"program_handle": self.program})
```

The program handle is passed as a query param per H1 docs, not in the body. On
success, the response includes the report ID, and the URL
`https://hackerone.com/reports/{id}` is printed.

**Report body** is assembled by `_build_h1_report_body`:

```python
def _build_h1_report_body(finding: dict) -> str:
    steps = finding.get("reproduction_steps", [])
    steps_str = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
    return f"""## Summary
{finding.get('description')}

## Impact
{finding.get('impact')}

## Steps to Reproduce
{steps_str}

## Affected URL
`{finding.get('url')}`"""
```

Numbered steps from `reproduction_steps` (a list populated by AI enrichment or
manually). H1 triagers expect this exact structure.

### Bugcrowd

Bugcrowd uses a Bearer token and the v4 `application/vnd.bugcrowd.v4+json` content
type:

```python
class BugcrowdClient:
    def _headers(self):
        return {
            "Authorization": f"Token {self.token}",
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Content-Type": "application/json",
        }
```

Severity is an integer (1–5) rather than a string:

```python
def _severity_map(self, severity: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}.get(
        severity.lower(), 3
    )
```

The `vrt_id` maps the internal vuln class to Bugcrowd's Vulnerability Rating
Taxonomy:

```python
def _vuln_class_to_vrt(vuln_class: str) -> str:
    mapping = {
        "XSS":           "cross_site_scripting_xss",
        "SQLi":          "sql_injection",
        "SSRF":          "server_side_request_forgery_ssrf",
        "IDOR":          "broken_object_level_authorization",
        "XXE":           "xml_external_entity_xxe",
        "Path Traversal":"path_traversal",
        "CORS":          "cross_origin_resource_sharing_cors",
        "Missing Rate Limiting": "lack_of_rate_limiting",
    }
    for key, vrt in mapping.items():
        if key.lower() in vuln_class.lower():
            return vrt
    return "other"
```

`if key.lower() in vuln_class.lower()` does substring matching, so `"Reflected XSS"`
and `"Stored XSS"` both map to `cross_site_scripting_xss`.

---

## report/cli.py — Report Commands

### `mewtwo report generate`

```python
@report_group.command("generate")
@click.option("--format", "fmt", type=click.Choice(["markdown","html","pdf"]), default="markdown")
@click.option("--ai-summary", is_flag=True)
@click.option("--output", type=click.Path())
def generate_cmd(fmt, ai_summary, output):
    findings = repo.for_target(target_row["id"])
    confirmed = [f for f in findings if f.get("status") in ("confirmed","draft")]

    summary = None
    if ai_summary:
        client = AIClient()
        summary = client.write_executive_summary(target_row["name"], confirmed)

    context = builder.build_report_context(target_row, confirmed, summary)

    if fmt == "markdown":
        content = renderer.render_markdown(context)
        path = ws / "reports" / f"report_{ts}.md"
        path.write_text(content)
    elif fmt == "html":
        content = renderer.render_html(context)
        path = ws / "reports" / f"report_{ts}.html"
        path.write_text(content)
    elif fmt == "pdf":
        path = ws / "reports" / f"report_{ts}.pdf"
        renderer.render_pdf(context, path)
```

Only `confirmed` and `draft` findings go into the report — hunt-discovered findings
in `DRAFT` status are included so you can generate a draft report mid-engagement.

### `mewtwo report submit`

```python
@report_group.command("submit")
@click.option("--platform", type=click.Choice(["hackerone","bugcrowd"]), required=True)
@click.option("--finding", "finding_id", required=True)
@click.option("--username")   # H1 only
@click.option("--token", required=True)
@click.option("--program", required=True)
def submit_cmd(platform, finding_id, username, token, program):
    finding_dict = repo._row_to_dict(dict(rows[0]))

    if platform == "hackerone":
        client = HackerOneClient(username, token, program)
    else:
        client = BugcrowdClient(token, program)

    client.submit(finding_dict)
```

Tokens are passed as CLI options (not stored in the DB) — so they come from your
shell environment via `--token $H1_TOKEN`, not written to disk.

---

## The Blank Page Bug

If `mewtwo report generate --format html` produces a blank page in the browser,
the likely cause is the Jinja2 template referencing a CSS or JS file via a relative
path that doesn't resolve when you open the file directly.

Check the template: if it has `<link rel="stylesheet" href="style.css">` and
`style.css` is not embedded or served from a local server, the browser loads
nothing. The fix is either to embed styles inline in the template or open the
report through a local server (`python -m http.server 8000` in the reports dir).
