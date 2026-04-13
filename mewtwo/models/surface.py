from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field


class VectorCategory(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    SSRF = "ssrf"
    INFORMATION_DISCLOSURE = "info_disclosure"
    BUSINESS_LOGIC = "business_logic"
    CLIENT_SIDE = "client_side"
    CONFIGURATION = "configuration"


class AttackVector(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    category: VectorCategory
    title: str
    description: str
    url: str
    parameters: list[str] = Field(default_factory=list)
    risk_rating: str = "medium"   # critical / high / medium / low
    rationale: str = ""
    source_recon_ids: list[str] = Field(default_factory=list)
    checked: bool = False
    finding_ids: list[str] = Field(default_factory=list)
