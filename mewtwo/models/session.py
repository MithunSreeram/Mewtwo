from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class SessionPhase(str, Enum):
    RECON = "recon"
    SURFACE = "surface"
    HUNT = "hunt"
    REPORTING = "reporting"


class SessionState(BaseModel):
    recon_completed: bool = False
    surface_mapped: bool = False
    hunt_in_progress: bool = False
    last_recon_at: datetime | None = None
    last_hunt_at: datetime | None = None
    subdomain_count: int = 0
    url_count: int = 0
    attack_vector_count: int = 0
    finding_count: int = 0


class Session(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    phase: SessionPhase = SessionPhase.RECON
    state: SessionState = Field(default_factory=SessionState)
    notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
