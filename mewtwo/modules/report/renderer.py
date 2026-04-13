"""Jinja2 report renderer."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def _get_env(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )


def _bundled_templates_dir() -> Path:
    return Path(__file__).parent / "templates"


def _user_templates_dir() -> Path:
    from ... import config
    return config.mewtwo_home() / "templates"


def _resolve_template(name: str) -> tuple[Environment, str]:
    user_dir = _user_templates_dir()
    if (user_dir / name).exists():
        return _get_env(user_dir), name
    return _get_env(_bundled_templates_dir()), name


def render_markdown(context: dict) -> str:
    env, name = _resolve_template("report.md.j2")
    return env.get_template(name).render(**context)


def render_html(context: dict) -> str:
    env, name = _resolve_template("report.html.j2")
    return env.get_template(name).render(**context)


def render_pdf(context: dict, output_path: Path) -> Path:
    """
    Render the HTML report and convert to PDF via weasyprint.

    Requires: pip install mewtwo[pdf]  (installs weasyprint + system deps)

    System deps on Debian/Ubuntu:
        apt install libpango-1.0-0 libpangoft2-1.0-0 libglib2.0-0
    """
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        raise ImportError(
            "weasyprint is required for PDF export.\n"
            "Install it with: pip install 'mewtwo[pdf]'\n"
            "System deps (Debian/Ubuntu): apt install libpango-1.0-0 libpangoft2-1.0-0"
        )

    html_content = render_html(context)

    # Extra print-friendly CSS
    print_css = CSS(string="""
        @page {
            margin: 2cm;
            size: A4;
        }
        body {
            font-family: 'DejaVu Sans', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.5;
            color: #1a1a1a;
        }
        .finding-card {
            page-break-inside: avoid;
            border: 1px solid #ddd;
            margin-bottom: 1.5em;
            padding: 1em;
            border-radius: 4px;
        }
        h1, h2, h3 { page-break-after: avoid; }
        pre, code { font-size: 9pt; }
        .severity-critical { color: #c0392b; }
        .severity-high     { color: #e67e22; }
        .severity-medium   { color: #f39c12; }
        .severity-low      { color: #27ae60; }
    """)

    HTML(string=html_content).write_pdf(
        str(output_path),
        stylesheets=[print_css],
        presentational_hints=True,
    )
    return output_path
