"""Shared Rich console and formatting helpers."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

_theme = Theme({
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "info": "bold cyan",
    "dim": "dim white",
    "critical": "bold red on white",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "informational": "dim white",
})

console = Console(theme=_theme, highlight=False)
err_console = Console(stderr=True, theme=_theme)


def success(msg: str) -> None:
    console.print(f"[success]✓[/success] {msg}")


def warn(msg: str) -> None:
    console.print(f"[warning]![/warning] {msg}")


def error(msg: str) -> None:
    err_console.print(f"[error]✗[/error] {msg}")


def info(msg: str) -> None:
    console.print(f"[info]→[/info] {msg}")


def severity_style(severity: str) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
    }.get(severity.lower(), "dim")
