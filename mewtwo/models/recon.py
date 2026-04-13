from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class Subdomain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    is_alive: bool = False
    status_code: int | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Port(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""


class Technology(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    host: str
    name: str
    version: str = ""
    category: str = ""
    confidence: int = 100


class DiscoveredURL(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    parameters: list[str] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)
    interesting_headers: dict = Field(default_factory=dict)
    source: str = "crawler"                                    # crawler | wayback
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class JSSecret(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    source_url: str
    secret_type: str   # "api_key", "jwt", "endpoint", "credential"
    value: str
    confidence: str = "medium"
