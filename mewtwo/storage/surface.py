from __future__ import annotations

import json

from ..models.surface import AttackVector
from .base import BaseRepository, _ser


class SurfaceRepository(BaseRepository):
    table_name = "attack_vectors"

    def upsert(self, vector: AttackVector) -> None:
        self.db["attack_vectors"].upsert({
            "id": vector.id,
            "target_id": vector.target_id,
            "category": vector.category.value,
            "title": vector.title,
            "description": vector.description,
            "url": vector.url,
            "parameters_json": json.dumps(vector.parameters),
            "risk_rating": vector.risk_rating,
            "rationale": vector.rationale,
            "source_recon_ids_json": json.dumps(vector.source_recon_ids),
            "checked": int(vector.checked),
            "finding_ids_json": json.dumps(vector.finding_ids),
        }, pk="id")

    def for_target(self, target_id: str, category: str | None = None) -> list[dict]:
        where = "target_id = ?"
        params: list = [target_id]
        if category:
            where += " AND category = ?"
            params.append(category)
        return [self._deserialize(dict(r)) for r in
                self.db["attack_vectors"].rows_where(where, params)]

    def mark_checked(self, vector_id: str) -> None:
        self.db["attack_vectors"].update(vector_id, {"checked": 1})

    def _deserialize(self, row: dict) -> dict:
        row["parameters"] = json.loads(row.pop("parameters_json", "[]") or "[]")
        row["source_recon_ids"] = json.loads(row.pop("source_recon_ids_json", "[]") or "[]")
        row["finding_ids"] = json.loads(row.pop("finding_ids_json", "[]") or "[]")
        row["checked"] = bool(row["checked"])
        return row
