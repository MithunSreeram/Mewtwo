"""Anthropic SDK wrapper — streaming, tool use, workspace context injection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import anthropic

from ... import config
from ...utils.console import console


class AIClient:
    """Thin wrapper around anthropic.Anthropic with workspace-context injection."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        key = api_key or config.anthropic_api_key()
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not set. Add it to .env or set the environment variable."
            )
        self.client = anthropic.Anthropic(api_key=key)
        self.model = model or config.model()

    # ------------------------------------------------------------------
    # Core completion
    # ------------------------------------------------------------------

    def complete(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> str:
        """Non-streaming completion. Returns text content."""
        kwargs: dict[str, Any] = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools
        response = self.client.messages.create(**kwargs)
        # Handle both text and tool_use blocks
        for block in response.content:
            if block.type == "text":
                return block.text
            if block.type == "tool_use":
                return json.dumps(block.input)
        return ""

    def stream(
        self,
        system: str,
        messages: list[dict],
        max_tokens: int = 4096,
    ) -> Iterator[str]:
        """Streaming completion — yields text deltas."""
        with self.client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        ) as stream:
            yield from stream.text_stream

    def complete_with_tool(
        self,
        system: str,
        messages: list[dict],
        tool: dict,
        max_tokens: int = 4096,
    ) -> dict:
        """Force a single tool call and return its input as a dict."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            tools=[tool],
            tool_choice={"type": "tool", "name": tool["name"]},
        )
        for block in response.content:
            if block.type == "tool_use":
                return block.input  # type: ignore[return-value]
        return {}

    # ------------------------------------------------------------------
    # Workspace context helpers
    # ------------------------------------------------------------------

    def workspace_context_snippet(self, db_path: Path | None = None) -> str:
        """Build a compact JSON summary of the active workspace for injection."""
        if not db_path or not db_path.exists():
            return ""
        try:
            import sqlite_utils
            from ...db import get_db
            db = get_db(db_path)
            targets = list(db["targets"].rows)
            target = targets[0] if targets else {}
            summary = {
                "target": target.get("name", "unknown"),
                "platform": target.get("platform", ""),
                "subdomains": db["subdomains"].count if "subdomains" in db.table_names() else 0,
                "urls": db["urls"].count if "urls" in db.table_names() else 0,
                "attack_vectors": db["attack_vectors"].count if "attack_vectors" in db.table_names() else 0,
                "findings": db["findings"].count if "findings" in db.table_names() else 0,
            }
            return json.dumps(summary, indent=2)
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # High-level task methods
    # ------------------------------------------------------------------

    def analyze_recon(
        self,
        subdomains: list[dict],
        technologies: list[dict],
        js_secrets: list[dict],
        db_path: Path | None = None,
    ) -> dict:
        """Analyze recon data and return attack vector suggestions."""
        from .prompts import recon_analysis_system, recon_analysis_user
        from .tools import ATTACK_VECTORS_TOOL

        system = recon_analysis_system(self.workspace_context_snippet(db_path))
        user_msg = recon_analysis_user(subdomains, technologies, js_secrets)
        return self.complete_with_tool(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            tool=ATTACK_VECTORS_TOOL,
        )

    def expand_attack_surface(
        self,
        recon_summary: dict,
        existing_vectors: list[dict],
        db_path: Path | None = None,
    ) -> dict:
        """Expand attack surface beyond deterministic heuristics."""
        from .prompts import surface_expansion_system, surface_expansion_user
        from .tools import ATTACK_VECTORS_TOOL

        system = surface_expansion_system(self.workspace_context_snippet(db_path))
        user_msg = surface_expansion_user(recon_summary, existing_vectors)
        return self.complete_with_tool(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            tool=ATTACK_VECTORS_TOOL,
        )

    def triage_finding(
        self,
        check_name: str,
        vector_url: str,
        evidence: str,
        db_path: Path | None = None,
    ) -> dict:
        """Triage hunt check evidence — is this a real finding?"""
        from .prompts import triage_system, triage_user
        from .tools import TRIAGE_TOOL

        system = triage_system(self.workspace_context_snippet(db_path))
        user_msg = triage_user(check_name, vector_url, evidence)
        return self.complete_with_tool(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            tool=TRIAGE_TOOL,
        )

    def generate_payloads(
        self,
        vuln_class: str,
        url: str,
        parameter: str,
        tech_stack: list[str],
    ) -> list[str]:
        """Generate context-aware payloads for a vuln class + endpoint."""
        from .prompts import payload_system, payload_user

        system = payload_system()
        user_msg = payload_user(vuln_class, url, parameter, tech_stack)
        result = self.complete(system=system, messages=[{"role": "user", "content": user_msg}])
        # Extract payloads from numbered/bulleted list
        lines = [l.strip().lstrip("•-*123456789.) ") for l in result.splitlines() if l.strip()]
        return [l for l in lines if l and not l.lower().startswith(("here", "payload", "these"))]

    def enrich_finding(self, finding_dict: dict, db_path: Path | None = None) -> dict:
        """Draft description, impact, reproduction steps, and remediation."""
        from .prompts import enrichment_system, enrichment_user
        from .tools import ENRICHMENT_TOOL

        system = enrichment_system(self.workspace_context_snippet(db_path))
        user_msg = enrichment_user(finding_dict)
        return self.complete_with_tool(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            tool=ENRICHMENT_TOOL,
            max_tokens=8096,
        )

    def write_executive_summary(self, target_name: str, findings: list[dict]) -> str:
        """Write an executive summary section for the report."""
        from .prompts import exec_summary_system, exec_summary_user

        system = exec_summary_system()
        user_msg = exec_summary_user(target_name, findings)
        return self.complete(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            max_tokens=2048,
        )

    def ask(self, question: str, context: str = "", stream: bool = False):
        """Free-form question with optional workspace context."""
        from .prompts import ask_system

        system = ask_system(context)
        msgs = [{"role": "user", "content": question}]
        if stream:
            return self.stream(system=system, messages=msgs)
        return self.complete(system=system, messages=msgs)
