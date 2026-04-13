"""Configuration management — env loading, path resolution, active workspace."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

def mewtwo_home() -> Path:
    """~/.mewtwo — global config/workspace root."""
    home = Path(os.environ.get("MEWTWO_HOME", Path.home() / ".mewtwo"))
    home.mkdir(parents=True, exist_ok=True)
    return home


def workspaces_dir() -> Path:
    default = mewtwo_home() / "workspaces"
    path = Path(os.environ.get("MEWTWO_WORKSPACES_DIR", default))
    path.mkdir(parents=True, exist_ok=True)
    return path


def workspace_path(slug: str) -> Path:
    return workspaces_dir() / slug


def current_symlink() -> Path:
    return mewtwo_home() / "current"


def active_workspace() -> Path | None:
    link = current_symlink()
    if link.exists() or link.is_symlink():
        target = link.resolve()
        if target.exists():
            return target
    return None


def set_active_workspace(slug: str) -> Path:
    ws = workspace_path(slug)
    if not ws.exists():
        raise FileNotFoundError(f"Workspace '{slug}' does not exist.")
    link = current_symlink()
    if link.is_symlink():
        link.unlink()
    link.symlink_to(ws)
    return ws


def require_active_workspace() -> Path:
    ws = active_workspace()
    if ws is None:
        raise RuntimeError(
            "No active workspace. Run [bold]mewtwo init <target>[/bold] first."
        )
    return ws


def db_path(ws: Path | None = None) -> Path:
    ws = ws or require_active_workspace()
    return ws / "mewtwo.db"


def reports_dir(ws: Path | None = None) -> Path:
    ws = ws or require_active_workspace()
    d = ws / "reports"
    d.mkdir(exist_ok=True)
    return d


def evidence_dir(ws: Path | None = None) -> Path:
    ws = ws or require_active_workspace()
    d = ws / "evidence"
    d.mkdir(exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def anthropic_api_key() -> str | None:
    return os.environ.get("ANTHROPIC_API_KEY")


def model() -> str:
    return os.environ.get("MEWTWO_MODEL", "claude-opus-4-5")


def proxy() -> str | None:
    return os.environ.get("MEWTWO_PROXY")


def timeout() -> int:
    return int(os.environ.get("MEWTWO_TIMEOUT", "30"))


def concurrency() -> int:
    return int(os.environ.get("MEWTWO_CONCURRENCY", "20"))
