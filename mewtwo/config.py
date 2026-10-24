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


def _active_pointer() -> Path:
    """Plain file holding the active workspace slug.

    A pointer file works on every platform; the old symlink approach failed on Windows
    without admin/Developer Mode (WinError 1314).
    """
    return mewtwo_home() / "active"


def _legacy_symlink() -> Path:
    return mewtwo_home() / "current"


def active_workspace() -> Path | None:
    # Preferred: pointer file with the slug.
    ptr = _active_pointer()
    try:
        if ptr.is_file():
            slug = ptr.read_text(encoding="utf-8").strip()
            if slug:
                ws = workspace_path(slug)
                if ws.exists():
                    return ws
    except OSError:
        pass

    # Backward compatibility: a legacy 'current' symlink from older versions.
    legacy = _legacy_symlink()
    try:
        if legacy.is_symlink() or legacy.exists():
            target = legacy.resolve()
            if target.exists():
                return target
    except OSError:
        pass
    return None


def set_active_workspace(slug: str) -> Path:
    ws = workspace_path(slug)
    if not ws.exists():
        raise FileNotFoundError(f"Workspace '{slug}' does not exist.")
    # Write the slug to a pointer file (portable; no symlink privileges needed).
    _active_pointer().write_text(slug, encoding="utf-8")
    # Clean up any stale legacy symlink so the two don't disagree.
    legacy = _legacy_symlink()
    try:
        if legacy.is_symlink():
            legacy.unlink()
    except OSError:
        pass
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


def rate_limit() -> float:
    """Max requests/second during active scanning. 0 = unlimited (default)."""
    try:
        return float(os.environ.get("MEWTWO_RATE_LIMIT", "0"))
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# Authenticated scanning
# ---------------------------------------------------------------------------

def auth_cookie() -> str | None:
    """Raw Cookie header value, e.g. 'session=abc; csrf=def'."""
    return os.environ.get("MEWTWO_AUTH_COOKIE") or None


def auth_bearer() -> str | None:
    """Bearer token (without the 'Bearer ' prefix)."""
    return os.environ.get("MEWTWO_AUTH_BEARER") or None


def auth_header() -> str | None:
    """Arbitrary extra auth header as 'Name: value'."""
    return os.environ.get("MEWTWO_AUTH_HEADER") or None


def build_auth(
    cookie: str | None = None,
    bearer: str | None = None,
    header: str | None = None,
) -> tuple[dict, dict]:
    """Build (headers, cookies) dicts from explicit args falling back to env.

    Used for authenticated scanning — most IDOR/authorization bugs only surface
    when requests carry a valid session.
    """
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    cookie_val = cookie or auth_cookie()
    if cookie_val:
        for part in cookie_val.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    bearer_val = bearer or auth_bearer()
    if bearer_val:
        headers["Authorization"] = f"Bearer {bearer_val}"

    header_val = header or auth_header()
    if header_val and ":" in header_val:
        name, value = header_val.split(":", 1)
        headers[name.strip()] = value.strip()

    return headers, cookies
