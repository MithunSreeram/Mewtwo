"""Workspace import/export — pack a workspace into a portable .mewtwo archive."""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from .utils.console import console, error, info, success, warn


# ------------------------------------------------------------------
# Export
# ------------------------------------------------------------------

def export_workspace(ws: Path, output: Path | None = None) -> Path:
    """
    Pack a workspace into a compressed .mewtwo tar archive.

    Archive layout:
        mewtwo-export/
          manifest.json          ← metadata
          mewtwo.db              ← SQLite database
          reports/               ← generated reports
          evidence/              ← evidence files (HTTP captures + attachments)

    Returns the path to the created archive.
    """
    if not ws.exists():
        raise FileNotFoundError(f"Workspace not found: {ws}")

    slug = ws.name
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    archive_name = f"{slug}_{timestamp}.mewtwo"
    dest = output or (ws.parent.parent / "exports" / archive_name)
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Build manifest
    manifest = {
        "mewtwo_version": "0.1.0",
        "workspace_slug": slug,
        "exported_at": datetime.utcnow().isoformat(),
        "files": [],
    }

    info(f"Exporting workspace [bold]{slug}[/bold]...")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp) / "mewtwo-export"
        tmp_root.mkdir()

        # Copy DB
        db_src = ws / "mewtwo.db"
        if db_src.exists():
            shutil.copy2(db_src, tmp_root / "mewtwo.db")
            manifest["files"].append("mewtwo.db")
            console.print(f"  [dim]+ mewtwo.db ({db_src.stat().st_size // 1024}KB)[/dim]")

        # Copy reports
        reports_src = ws / "reports"
        if reports_src.exists() and any(reports_src.iterdir()):
            shutil.copytree(reports_src, tmp_root / "reports")
            manifest["files"].append("reports/")
            count = sum(1 for _ in reports_src.rglob("*") if _.is_file())
            console.print(f"  [dim]+ reports/ ({count} files)[/dim]")

        # Copy evidence
        evidence_src = ws / "evidence"
        if evidence_src.exists() and any(evidence_src.iterdir()):
            shutil.copytree(evidence_src, tmp_root / "evidence")
            manifest["files"].append("evidence/")
            count = sum(1 for _ in evidence_src.rglob("*") if _.is_file())
            console.print(f"  [dim]+ evidence/ ({count} files)[/dim]")

        # Write manifest
        (tmp_root / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # Create archive
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(tmp_root, arcname="mewtwo-export")

    size_kb = dest.stat().st_size // 1024
    success(f"Workspace exported: [bold]{dest}[/bold] ({size_kb}KB)")
    return dest


# ------------------------------------------------------------------
# Import
# ------------------------------------------------------------------

def import_workspace(archive: Path, workspaces_dir: Path, activate: bool = True) -> str:
    """
    Unpack a .mewtwo archive into a workspace.

    Returns the workspace slug.
    Raises FileExistsError if the workspace already exists (unless --overwrite).
    """
    if not archive.exists():
        raise FileNotFoundError(f"Archive not found: {archive}")

    if not tarfile.is_tarfile(archive):
        raise ValueError(f"Not a valid .mewtwo archive: {archive}")

    info(f"Importing workspace from [bold]{archive.name}[/bold]...")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(tmp_path)

        extracted_root = tmp_path / "mewtwo-export"
        if not extracted_root.exists():
            raise ValueError("Archive does not contain a valid mewtwo-export directory.")

        # Read manifest
        manifest_path = extracted_root / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("Archive is missing manifest.json.")

        manifest = json.loads(manifest_path.read_text())
        slug = manifest.get("workspace_slug", archive.stem.split("_")[0])
        exported_at = manifest.get("exported_at", "unknown")

        console.print(f"  Slug: [bold]{slug}[/bold]")
        console.print(f"  Exported at: [dim]{exported_at}[/dim]")
        console.print(f"  Files: {', '.join(manifest.get('files', []))}")

        ws_dest = workspaces_dir / slug
        if ws_dest.exists():
            raise FileExistsError(
                f"Workspace '{slug}' already exists at {ws_dest}. "
                "Use --overwrite to replace it."
            )

        ws_dest.mkdir(parents=True)
        (ws_dest / "reports").mkdir(exist_ok=True)
        (ws_dest / "evidence").mkdir(exist_ok=True)

        # Restore DB
        db_src = extracted_root / "mewtwo.db"
        if db_src.exists():
            shutil.copy2(db_src, ws_dest / "mewtwo.db")
            console.print("  [dim]Restored mewtwo.db[/dim]")

        # Restore reports
        reports_src = extracted_root / "reports"
        if reports_src.exists():
            shutil.copytree(reports_src, ws_dest / "reports", dirs_exist_ok=True)
            console.print("  [dim]Restored reports/[/dim]")

        # Restore evidence
        evidence_src = extracted_root / "evidence"
        if evidence_src.exists():
            shutil.copytree(evidence_src, ws_dest / "evidence", dirs_exist_ok=True)
            console.print("  [dim]Restored evidence/[/dim]")

    success(f"Workspace imported: [bold]{slug}[/bold] → {ws_dest}")
    return slug
