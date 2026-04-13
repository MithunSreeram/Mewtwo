"""Database bootstrap — SQLite via sqlite-utils, schema creation."""

from __future__ import annotations

from pathlib import Path

import sqlite_utils


# ---------------------------------------------------------------------------
# Connection factory
# ---------------------------------------------------------------------------

def get_db(db_path: Path) -> sqlite_utils.Database:
    """Return an open sqlite-utils Database, creating schema if needed."""
    db = sqlite_utils.Database(db_path)
    _ensure_schema(db)
    return db


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def _ensure_schema(db: sqlite_utils.Database) -> None:
    """Idempotently create all tables."""

    # targets
    if "targets" not in db.table_names():
        db["targets"].create({
            "id": str,
            "name": str,
            "slug": str,
            "platform": str,
            "program_url": str,
            "notes": str,
            "created_at": str,
            "updated_at": str,
        }, pk="id")
        db["targets"].create_index(["slug"], unique=True)

    # scope
    if "scope" not in db.table_names():
        db["scope"].create({
            "id": str,
            "target_id": str,
            "pattern": str,
            "scope_type": str,
            "notes": str,
        }, pk="id", foreign_keys=[("target_id", "targets", "id")])

    # sessions
    if "sessions" not in db.table_names():
        db["sessions"].create({
            "id": str,
            "target_id": str,
            "phase": str,
            "state_json": str,
            "notes": str,
            "created_at": str,
            "updated_at": str,
        }, pk="id", foreign_keys=[("target_id", "targets", "id")])

    # recon — subdomains
    if "subdomains" not in db.table_names():
        db["subdomains"].create({
            "id": str,
            "target_id": str,
            "hostname": str,
            "ip_addresses_json": str,
            "sources_json": str,
            "is_alive": int,
            "status_code": int,
            "discovered_at": str,
        }, pk="id")
        db["subdomains"].create_index(["target_id", "hostname"], unique=True, if_not_exists=True)

    # recon — ports
    if "ports" not in db.table_names():
        db["ports"].create({
            "id": str,
            "target_id": str,
            "host": str,
            "port": int,
            "protocol": str,
            "service": str,
            "version": str,
            "banner": str,
        }, pk="id")

    # recon — technologies
    if "technologies" not in db.table_names():
        db["technologies"].create({
            "id": str,
            "target_id": str,
            "host": str,
            "name": str,
            "version": str,
            "category": str,
            "confidence": int,
        }, pk="id")

    # recon — urls
    if "urls" not in db.table_names():
        db["urls"].create({
            "id": str,
            "target_id": str,
            "url": str,
            "method": str,
            "status_code": int,
            "content_type": str,
            "parameters_json": str,
            "forms_json": str,
            "interesting_headers_json": str,
        }, pk="id")
        db["urls"].create_index(["target_id", "url"], unique=True, if_not_exists=True)

    # recon — js_secrets
    if "js_secrets" not in db.table_names():
        db["js_secrets"].create({
            "id": str,
            "target_id": str,
            "source_url": str,
            "secret_type": str,
            "value": str,
            "confidence": str,
        }, pk="id")

    # attack_vectors
    if "attack_vectors" not in db.table_names():
        db["attack_vectors"].create({
            "id": str,
            "target_id": str,
            "category": str,
            "title": str,
            "description": str,
            "url": str,
            "parameters_json": str,
            "risk_rating": str,
            "rationale": str,
            "source_recon_ids_json": str,
            "checked": int,
            "finding_ids_json": str,
        }, pk="id")

    # findings
    if "findings" not in db.table_names():
        db["findings"].create({
            "id": str,
            "target_id": str,
            "title": str,
            "vuln_class": str,
            "severity": str,
            "status": str,
            "cvss_json": str,
            "url": str,
            "parameter": str,
            "description": str,
            "impact": str,
            "reproduction_steps_json": str,
            "evidence_json": str,
            "remediation": str,
            "references_json": str,
            "ai_generated": int,
            "discovered_at": str,
            "updated_at": str,
            "tags_json": str,
        }, pk="id")
