from __future__ import annotations

import sqlite_utils

from ..models.target import Target, ScopeEntry
from .base import BaseRepository, _ser


class TargetRepository(BaseRepository):
    table_name = "targets"

    def upsert(self, target: Target) -> None:
        self.db["targets"].upsert({
            "id": target.id,
            "name": target.name,
            "slug": target.slug,
            "platform": target.platform,
            "program_url": target.program_url,
            "notes": target.notes,
            "created_at": _ser(target.created_at),
            "updated_at": _ser(target.updated_at),
        }, pk="id")

    def get_by_slug(self, slug: str) -> dict | None:
        rows = list(self.db["targets"].rows_where("slug = ?", [slug]))
        return dict(rows[0]) if rows else None

    def list_all(self) -> list[dict]:
        return [dict(r) for r in self.db["targets"].rows]


class ScopeRepository(BaseRepository):
    table_name = "scope"

    def add(self, entry: ScopeEntry) -> None:
        self.db["scope"].insert({
            "id": entry.id,
            "target_id": entry.target_id,
            "pattern": entry.pattern,
            "scope_type": entry.scope_type.value,
            "notes": entry.notes,
        }, ignore=True)

    def for_target(self, target_id: str) -> list[dict]:
        return [dict(r) for r in self.db["scope"].rows_where(
            "target_id = ?", [target_id]
        )]

    def remove(self, target_id: str, pattern: str) -> None:
        self.db["scope"].delete_where(
            "target_id = ? AND pattern = ?", [target_id, pattern]
        )
