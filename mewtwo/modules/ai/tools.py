"""Claude tool definitions for structured output from AI calls."""

from __future__ import annotations

ATTACK_VECTORS_TOOL = {
    "name": "report_attack_vectors",
    "description": "Report a list of identified attack vectors from recon/surface analysis.",
    "input_schema": {
        "type": "object",
        "properties": {
            "vectors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "enum": [
                                "authentication", "authorization", "injection",
                                "ssrf", "info_disclosure", "business_logic",
                                "client_side", "configuration",
                            ],
                        },
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "url": {"type": "string"},
                        "parameters": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "risk_rating": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "rationale": {"type": "string"},
                    },
                    "required": ["category", "title", "description", "url", "risk_rating", "rationale"],
                },
            }
        },
        "required": ["vectors"],
    },
}

TRIAGE_TOOL = {
    "name": "triage_finding",
    "description": "Return triage decision for a potential security finding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "is_finding": {"type": "boolean"},
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "informational"],
            },
            "vuln_class": {"type": "string"},
            "title": {"type": "string"},
            "impact": {"type": "string"},
            "confidence": {
                "type": "string",
                "enum": ["confirmed", "likely", "possible", "unlikely"],
            },
            "follow_up": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["is_finding", "severity", "confidence", "reason"],
    },
}

ENRICHMENT_TOOL = {
    "name": "enrich_finding",
    "description": "Return enriched vulnerability report sections.",
    "input_schema": {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "impact": {"type": "string"},
            "reproduction_steps": {
                "type": "array",
                "items": {"type": "string"},
            },
            "remediation": {"type": "string"},
            "references": {
                "type": "array",
                "items": {"type": "string"},
            },
            "suggested_severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "informational"],
            },
        },
        "required": ["description", "impact", "reproduction_steps", "remediation"],
    },
}

CVSS_TOOL = {
    "name": "suggest_cvss",
    "description": "Suggest CVSS 3.1 vector components for a vulnerability.",
    "input_schema": {
        "type": "object",
        "properties": {
            "attack_vector": {"type": "string", "enum": ["N", "A", "L", "P"]},
            "attack_complexity": {"type": "string", "enum": ["L", "H"]},
            "privileges_required": {"type": "string", "enum": ["N", "L", "H"]},
            "user_interaction": {"type": "string", "enum": ["N", "R"]},
            "scope": {"type": "string", "enum": ["U", "C"]},
            "confidentiality": {"type": "string", "enum": ["N", "L", "H"]},
            "integrity": {"type": "string", "enum": ["N", "L", "H"]},
            "availability": {"type": "string", "enum": ["N", "L", "H"]},
            "rationale": {"type": "string"},
        },
        "required": [
            "attack_vector", "attack_complexity", "privileges_required",
            "user_interaction", "scope", "confidentiality", "integrity",
            "availability", "rationale",
        ],
    },
}
