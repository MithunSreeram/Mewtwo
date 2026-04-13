from __future__ import annotations

import json
from datetime import datetime

from ..models.session import Session, SessionPhase
from .base import BaseRepository, _ser


class SessionRepository(BaseRepository):
    table_name = "sessions"

    def upsert(self, session: Session) -> None:
        self.db["sessions"].upsert({
            "id": session.id,
            "target_id": session.target_id,
            "phase": session.phase.value,
            "state_json": session.state.model_dump_json(),
            "notes": session.notes,
            "created_at": _ser(session.created_at),
            "updated_at": _ser(session.updated_at),
        }, pk="id")

    def for_target(self, target_id: str) -> dict | None:
        rows = list(self.db["sessions"].rows_where(
            "target_id = ? ORDER BY created_at DESC LIMIT 1", [target_id]
        ))
        if not rows:
            return None
        row = dict(rows[0])
        row["state"] = json.loads(row.pop("state_json"))
        return row

    def update_phase(self, session_id: str, phase: SessionPhase) -> None:
        self.db["sessions"].update(session_id, {
            "phase": phase.value,
            "updated_at": datetime.utcnow().isoformat(),
        })
