"""Base class for all hunt checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from ....models.surface import AttackVector
    from ....modules.ai.client import AIClient


@dataclass
class FindingDraft:
    """Minimal finding produced by a check — enriched later if confirmed."""
    title: str
    vuln_class: str
    severity: str
    url: str
    parameter: str = ""
    description: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    # Raw HTTP proof — populated by checks that capture request/response
    raw_request: str = ""
    raw_response: str = ""


class BaseCheck(ABC):
    name: str = ""
    description: str = ""
    vuln_class: str = ""
    references: list[str] = []
    # Categories this check applies to (from VectorCategory values)
    applicable_categories: list[str] = []

    @abstractmethod
    async def run(
        self,
        vector: "AttackVector",
        client: httpx.AsyncClient,
        ai: "AIClient | None" = None,
    ) -> list[FindingDraft]:
        """Execute the check against the vector. Return confirmed/likely findings."""
        ...

    def _evidence_snippet(self, request: str, response: str, max_len: int = 500) -> str:
        """Format a request/response snippet for evidence."""
        return f"Request:\n{request[:200]}\n\nResponse:\n{response[:max_len]}"
