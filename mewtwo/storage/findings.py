from __future__ import annotations

import json
from datetime import datetime

from ..models.finding import Finding
from .base import BaseRepository, _ser


class FindingRepository(BaseRepository):
    table_name = "findings"
    json_fields = [
        "reproduction_steps_json", "evidence_json",
        "references_json", "tags_json", "cvss_json",
    ]
    bool_fields = ["ai_generated"]

    def upsert(self, finding: Finding) -> None:
        self.db["findings"].upsert({
            "id": finding.id,
            "target_id": finding.target_id,
            "title": finding.title,
            "vuln_class": finding.vuln_class,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "cvss_json": json.dumps(finding.cvss.model_dump() if finding.cvss else None),
            "url": finding.url,
            "parameter": finding.parameter,
            "description": finding.description,
            "impact": finding.impact,
            "reproduction_steps_json": json.dumps(finding.reproduction_steps),
            "evidence_json": json.dumps([e.model_dump() for e in finding.evidence]),
            "remediation": finding.remediation,
            "references_json": json.dumps(finding.references),
            "ai_generated": int(finding.ai_generated),
            "discovered_at": _ser(finding.discovered_at),
            "updated_at": _ser(finding.updated_at),
            "tags_json": json.dumps(finding.tags),
        }, pk="id")

    def for_target(
        self,
        target_id: str,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        where = "target_id = ?"
        params: list = [target_id]
        if severity:
            where += " AND severity = ?"
            params.append(severity)
        if status:
            where += " AND status = ?"
            params.append(status)
        return [self._row_to_dict(dict(r))
                for r in self.db["findings"].rows_where(where, params)]

    def update_status(self, finding_id: str, status: str) -> None:
        self.db["findings"].update(finding_id, {
            "status": status,
            "updated_at": datetime.utcnow().isoformat(),
        })

    def update_fields(self, finding_id: str, **fields) -> None:
        fields["updated_at"] = datetime.utcnow().isoformat()
        self.db["findings"].update(finding_id, fields)
