from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    CLOSED = "closed"


class CVSSVector(BaseModel):
    attack_vector: str = "N"       # N/A/L/P
    attack_complexity: str = "L"   # L/H
    privileges_required: str = "N" # N/L/H
    user_interaction: str = "N"    # N/R
    scope: str = "U"               # U/C
    confidentiality: str = "N"     # N/L/H
    integrity: str = "N"
    availability: str = "N"
    score: float = 0.0
    vector_string: str = ""


class Evidence(BaseModel):
    kind: str                      # "request", "response", "screenshot", "note"
    content: str
    caption: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    title: str
    vuln_class: str
    severity: Severity
    status: FindingStatus = FindingStatus.DRAFT
    cvss: CVSSVector | None = None
    url: str
    parameter: str = ""
    description: str = ""
    impact: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    ai_generated: bool = False
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)
