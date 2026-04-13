from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ScopeType(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    INFORMATIONAL = "informational"


class ScopeEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    pattern: str
    scope_type: ScopeType = ScopeType.IN_SCOPE
    notes: str = ""


class Target(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    slug: str
    platform: str = ""
    program_url: str = ""
    notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
