"""Base repository with generic CRUD helpers."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import sqlite_utils
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def _ser(value: Any) -> Any:
    """Serialize a value for SQLite storage."""
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bool):
        return int(value)
    return value


def _deserialize_row(row: dict, json_fields: list[str], bool_fields: list[str]) -> dict:
    for f in json_fields:
        if f in row and row[f] is not None:
            row[f] = json.loads(row[f])
    for f in bool_fields:
        if f in row:
            row[f] = bool(row[f])
    return row


class BaseRepository:
    table_name: str
    json_fields: list[str] = []
    bool_fields: list[str] = []

    def __init__(self, db: sqlite_utils.Database):
        self.db = db

    @property
    def table(self) -> sqlite_utils.Table:
        return self.db[self.table_name]  # type: ignore[return-value]

    def _row_to_dict(self, row: dict) -> dict:
        return _deserialize_row(dict(row), self.json_fields, self.bool_fields)

    def get(self, id: str) -> dict | None:
        rows = list(self.table.rows_where("id = ?", [id]))
        if not rows:
            return None
        return self._row_to_dict(dict(rows[0]))

    def all(self, **where_kwargs: Any) -> list[dict]:
        if where_kwargs:
            clause = " AND ".join(f"{k} = ?" for k in where_kwargs)
            params = list(where_kwargs.values())
            rows = self.table.rows_where(clause, params)
        else:
            rows = self.table.rows
        return [self._row_to_dict(dict(r)) for r in rows]

    def delete(self, id: str) -> None:
        self.table.delete_where("id = ?", [id])

    def count(self, **where_kwargs: Any) -> int:
        if where_kwargs:
            clause = " AND ".join(f"{k} = ?" for k in where_kwargs)
            params = list(where_kwargs.values())
            return self.table.count_where(clause, params)
        return self.table.count
