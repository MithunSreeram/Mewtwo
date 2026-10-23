"""Bounded agentic hunt loop — Claude drives an evidence-based probe of one endpoint.

Unlike the fixed-payload checks, this lets the model form hypotheses, send requests via a
constrained ``http_request`` tool, read the responses, and iterate until it concludes. It is
deliberately hemmed in:

* host-locked   — every request must target the original endpoint's host
* scope-locked  — requests are routed through the same scope/rate-limit transport as the hunt
* non-destructive — destructive payloads (DROP/DELETE/rm -rf/...) are refused, not sent
* step-budgeted — a hard cap on the number of requests
* aggressive-tier — the CLI only exposes it under the aggressive tier with authorisation

It returns ``(conclusion_dict, transcript)`` where transcript is a list of the probes made.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from ...utils.console import info, warn
from ...utils.throttle import AsyncRateLimiter
from ...utils.validators import in_scope
from ..hunt.netguard import ScopeRateLimitTransport, OutOfScopeError
from ..hunt.safety import is_destructive

if TYPE_CHECKING:
    from .client import AIClient

_MAX_STEPS = 12
_MAX_BODY_CHARS = 6000  # truncate responses fed back to the model


async def agentic_hunt(
    ai: "AIClient",
    url: str,
    vector_hint: str = "",
    scope_patterns: list[str] | None = None,
    rate: float = 0.0,
    max_steps: int = _MAX_STEPS,
    auth: tuple[dict, dict] | None = None,
) -> tuple[dict, list[dict]]:
    """Run the bounded agentic hunt. Returns (conclusion, transcript)."""
    from .prompts import agentic_hunt_system, agentic_hunt_user
    from .tools import HTTP_REQUEST_TOOL, CONCLUDE_TOOL

    target_host = urlparse(url).netloc.split(":")[0]
    # Lock to the target host; fold in any workspace scope patterns too.
    host_scope = list(scope_patterns or []) + [target_host, f"*.{target_host}"]

    limiter = AsyncRateLimiter(rate) if rate and rate > 0 else None
    transport = ScopeRateLimitTransport(
        httpx.AsyncHTTPTransport(verify=False),
        scope_patterns=host_scope,
        limiter=limiter,
        enforce_scope=True,
    )
    auth_headers, auth_cookies = auth or ({}, {})

    transcript: list[dict] = []
    system = agentic_hunt_system(ai.workspace_context_snippet())
    messages: list[dict] = [
        {"role": "user", "content": agentic_hunt_user(url, vector_hint)}
    ]
    tools = [HTTP_REQUEST_TOOL, CONCLUDE_TOOL]

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        transport=transport,
        headers={"User-Agent": "Mozilla/5.0", **auth_headers},
        cookies=auth_cookies,
    ) as client:
        for step in range(max_steps):
            response = ai.client.messages.create(
                model=ai.model,
                max_tokens=2048,
                system=system,
                messages=messages,
                tools=tools,
            )

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                # Model answered in prose without a tool — treat as inconclusive stop.
                text = next((b.text for b in response.content if b.type == "text"), "")
                return (
                    {"is_vulnerable": False, "summary": text or "No conclusion reached.",
                     "confidence": "unlikely"},
                    transcript,
                )

            # Record the assistant turn verbatim so tool_results line up.
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for tu in tool_uses:
                if tu.name == "conclude":
                    return dict(tu.input), transcript

                if tu.name == "http_request":
                    result_text = await _execute_request(client, tu.input, target_host, transcript)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": result_text,
                    })

            messages.append({"role": "user", "content": tool_results})

    warn(f"Agentic hunt hit the {max_steps}-step budget without concluding.")
    return (
        {"is_vulnerable": False, "summary": "Step budget exhausted without a verdict.",
         "confidence": "possible"},
        transcript,
    )


async def _execute_request(
    client: httpx.AsyncClient,
    req: dict,
    target_host: str,
    transcript: list[dict],
) -> str:
    """Execute one model-requested HTTP probe under the safety constraints."""
    method = str(req.get("method", "GET")).upper()
    req_url = req.get("url", "")
    headers = req.get("headers") or {}
    body = req.get("body") or ""
    hypothesis = req.get("hypothesis", "")

    # Host lock (belt-and-braces alongside the transport scope check).
    if urlparse(req_url).netloc.split(":")[0] != target_host:
        return f"REFUSED: request to a different host than the target ({target_host})."

    # Non-destructive guard.
    if is_destructive(req_url) or is_destructive(body):
        return "REFUSED: destructive payload blocked by safety policy. Try a non-destructive probe."

    info(f"[agent] {method} {req_url}  ({hypothesis[:60]})")
    try:
        resp = await client.request(method, req_url, headers=headers, content=body or None)
    except OutOfScopeError:
        return "REFUSED: out of scope."
    except Exception as e:
        transcript.append({"method": method, "url": req_url, "error": str(e)})
        return f"ERROR: {e}"

    snippet = resp.text[:_MAX_BODY_CHARS]
    transcript.append({
        "method": method, "url": req_url, "hypothesis": hypothesis,
        "status": resp.status_code, "bytes": len(resp.text),
    })
    header_lines = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return (
        f"HTTP {resp.status_code}\n{header_lines}\n\n{snippet}"
        + ("\n...[truncated]" if len(resp.text) > _MAX_BODY_CHARS else "")
    )
