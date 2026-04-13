"""Platform submission — push confirmed findings to HackerOne or Bugcrowd via API."""

from __future__ import annotations

import json
from typing import Any

import httpx

from ...utils.console import info, success, warn, error

# ---------------------------------------------------------------------------
# HackerOne
# ---------------------------------------------------------------------------

_H1_API = "https://api.hackerone.com/v1"


class HackerOneClient:
    """Thin wrapper around the HackerOne v1 REST API."""

    def __init__(self, username: str, api_token: str, program_handle: str):
        self.auth = (username, api_token)
        self.program = program_handle

    def _headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _severity_map(self, severity: str) -> str:
        return {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "none",
        }.get(severity.lower(), "none")

    def submit(self, finding: dict) -> dict:
        """
        Submit a finding as a report to HackerOne.
        Returns the created report dict on success.
        """
        severity = self._severity_map(finding.get("severity", "medium"))
        title = finding.get("title", "Untitled Finding")
        description = _build_h1_report_body(finding)

        payload: dict[str, Any] = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": title,
                    "vulnerability_information": description,
                    "severity_rating": severity,
                    "impact": finding.get("impact", ""),
                    "weakness_id": None,
                },
                "relationships": {
                    "severity": {
                        "data": {
                            "type": "severity",
                            "attributes": {
                                "rating": severity,
                            }
                        }
                    }
                }
            }
        }

        url = f"{_H1_API}/reports"
        # Include program handle as query param per H1 docs
        params = {"program_handle": self.program}

        with httpx.Client(auth=self.auth, timeout=30) as client:
            resp = client.post(url, json=payload, headers=self._headers(), params=params)

        if resp.status_code in (200, 201):
            data = resp.json()
            report_id = data.get("data", {}).get("id", "?")
            report_url = f"https://hackerone.com/reports/{report_id}"
            success(f"HackerOne report created: #{report_id} — {report_url}")
            return data
        else:
            error(f"HackerOne submission failed: {resp.status_code} — {resp.text[:200]}")
            return {"error": resp.text, "status_code": resp.status_code}

    def list_reports(self, state: str = "new") -> list[dict]:
        """List reports for the program (for status checking)."""
        with httpx.Client(auth=self.auth, timeout=30) as client:
            resp = client.get(
                f"{_H1_API}/reports",
                headers=self._headers(),
                params={"filter[state][]": state, "filter[program][]": self.program},
            )
        if resp.status_code == 200:
            return resp.json().get("data", [])
        warn(f"Failed to list H1 reports: {resp.status_code}")
        return []


# ---------------------------------------------------------------------------
# Bugcrowd
# ---------------------------------------------------------------------------

_BC_API = "https://api.bugcrowd.com"


class BugcrowdClient:
    """Thin wrapper around the Bugcrowd v4 REST API."""

    def __init__(self, api_token: str, program_code: str):
        self.token = api_token
        self.program = program_code

    def _headers(self) -> dict:
        return {
            "Authorization": f"Token {self.token}",
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Content-Type": "application/json",
        }

    def _severity_map(self, severity: str) -> int:
        # Bugcrowd uses 1 (P1/critical) → 5 (P5/informational)
        return {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "informational": 5,
        }.get(severity.lower(), 3)

    def submit(self, finding: dict) -> dict:
        """Submit a finding as a submission to Bugcrowd."""
        severity = self._severity_map(finding.get("severity", "medium"))
        description = _build_bc_report_body(finding)

        payload: dict[str, Any] = {
            "data": {
                "type": "submission",
                "attributes": {
                    "title": finding.get("title", "Untitled Finding"),
                    "description": description,
                    "severity": severity,
                    "vrt_id": _vuln_class_to_vrt(finding.get("vuln_class", "")),
                    "extra_info": finding.get("url", ""),
                },
                "relationships": {
                    "target": {
                        "data": {
                            "type": "target",
                            "attributes": {"uri": finding.get("url", "")},
                        }
                    }
                }
            }
        }

        url = f"{_BC_API}/programs/{self.program}/submissions"
        with httpx.Client(timeout=30) as client:
            resp = client.post(url, json=payload, headers=self._headers())

        if resp.status_code in (200, 201):
            data = resp.json()
            ref = data.get("data", {}).get("attributes", {}).get("reference_number", "?")
            success(f"Bugcrowd submission created: #{ref}")
            return data
        else:
            error(f"Bugcrowd submission failed: {resp.status_code} — {resp.text[:200]}")
            return {"error": resp.text, "status_code": resp.status_code}


# ---------------------------------------------------------------------------
# Report body formatters
# ---------------------------------------------------------------------------

def _build_h1_report_body(finding: dict) -> str:
    steps = finding.get("reproduction_steps", [])
    steps_str = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps else finding.get("description", "")
    refs = "\n".join(f"- {r}" for r in finding.get("references", []))
    return f"""## Summary

{finding.get('description', '')}

## Impact

{finding.get('impact', 'Not specified.')}

## Steps to Reproduce

{steps_str}

## Affected URL

`{finding.get('url', 'N/A')}`

## Parameter

`{finding.get('parameter', 'N/A')}`

## References

{refs or 'N/A'}
"""


def _build_bc_report_body(finding: dict) -> str:
    steps = finding.get("reproduction_steps", [])
    steps_str = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps else finding.get("description", "")
    return f"""{finding.get('description', '')}

**Impact:** {finding.get('impact', 'Not specified.')}

**Steps to Reproduce:**
{steps_str}

**Affected URL:** {finding.get('url', 'N/A')}
"""


def _vuln_class_to_vrt(vuln_class: str) -> str:
    """Map internal vuln class names to Bugcrowd VRT IDs (best-effort)."""
    mapping = {
        "XSS": "cross_site_scripting_xss",
        "SQLi": "sql_injection",
        "SSRF": "server_side_request_forgery_ssrf",
        "IDOR": "broken_object_level_authorization",
        "XXE": "xml_external_entity_xxe",
        "Path Traversal": "path_traversal",
        "CORS": "cross_origin_resource_sharing_cors",
        "Open Redirect": "open_redirect",
        "Missing Rate Limiting": "lack_of_rate_limiting",
    }
    for key, vrt in mapping.items():
        if key.lower() in vuln_class.lower():
            return vrt
    return "other"
