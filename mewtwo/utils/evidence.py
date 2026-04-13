"""Evidence capture — saves raw HTTP request/response pairs to disk."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import httpx


def format_request(req: httpx.Request) -> str:
    """Render an httpx.Request as a raw HTTP string."""
    lines = [f"{req.method} {req.url.raw_path.decode()} HTTP/1.1"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    try:
        body = req.content.decode("utf-8", errors="replace")
        if body:
            lines.append(body)
    except Exception:
        pass
    return "\n".join(lines)


def format_response(resp: httpx.Response) -> str:
    """Render an httpx.Response as a raw HTTP string."""
    lines = [f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    try:
        lines.append(resp.text[:4096])   # cap at 4 KB
    except Exception:
        pass
    return "\n".join(lines)


def save_evidence(
    evidence_dir: Path,
    finding_id: str,
    label: str,
    raw_request: str,
    raw_response: str,
    notes: str = "",
) -> Path:
    """
    Write a request/response pair to disk.

    Returns the path to the saved .txt file.
    Evidence is stored as:
      <evidence_dir>/<finding_id>/<label>.txt
    """
    dest = evidence_dir / finding_id
    dest.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{label}_{ts}.txt"
    filepath = dest / filename

    content_parts = [
        "=" * 60,
        f"FINDING:  {finding_id}",
        f"LABEL:    {label}",
        f"CAPTURED: {datetime.utcnow().isoformat()}",
        "=" * 60,
        "",
        "──── REQUEST ────────────────────────────────────────────",
        raw_request,
        "",
        "──── RESPONSE ───────────────────────────────────────────",
        raw_response,
    ]
    if notes:
        content_parts += ["", "──── NOTES ──────────────────────────────────────────────", notes]

    filepath.write_text("\n".join(content_parts), encoding="utf-8")
    return filepath


def save_evidence_from_httpx(
    evidence_dir: Path,
    finding_id: str,
    label: str,
    request: httpx.Request,
    response: httpx.Response,
    notes: str = "",
) -> Path:
    """Convenience wrapper: format httpx objects then save."""
    return save_evidence(
        evidence_dir=evidence_dir,
        finding_id=finding_id,
        label=label,
        raw_request=format_request(request),
        raw_response=format_response(response),
        notes=notes,
    )
