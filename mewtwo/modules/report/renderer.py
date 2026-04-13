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
