"""FastAPI app for the Mewtwo local dashboard.

Localhost-only by design. Read endpoints expose workspace data; action endpoints kick off
recon/surface/hunt as background jobs whose progress streams over a WebSocket. Secrets
(ANTHROPIC_API_KEY, auth cookies/tokens) are NEVER serialised to the browser — the UI only
learns whether they are configured, as booleans.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import config
from ..db import get_db
from .jobs import JobHub

_STATIC = Path(__file__).parent / "static"


# Request bodies must be module-level: with `from __future__ import annotations`, route
# annotations are strings that FastAPI resolves against this module's globals, so a model
# defined inside create_app() would not resolve (and silently fall back to query params).
class ReconReq(BaseModel):
    passive_only: bool = False
    force: bool = False
    steps: list[str] | None = None


class HuntReq(BaseModel):
    tier: str = "normal"
    rate: float = 0.0
    enforce_scope: bool = True
    use_auth: bool = False


class WorkspaceReq(BaseModel):
    name: str
    domain: str = ""
    platform: str = ""
    program_url: str = ""


class ScopeReq(BaseModel):
    pattern: str
    scope_type: str = "in"   # in | out | info
    notes: str = ""


# --------------------------------------------------------------------------- helpers

def _active_db():
    ws = config.active_workspace()
    if ws is None:
        raise HTTPException(404, "No active workspace. Run `mewtwo init <target>` first.")
    return ws, get_db(config.db_path(ws))


def _target(db):
    rows = list(db["targets"].rows)
    if not rows:
        raise HTTPException(404, "Workspace has no target.")
    return rows[0]


def _count(db, table: str, where: str = "", params=None) -> int:
    if table not in db.table_names():
        return 0
    if where:
        return db[table].count_where(where, params or [])
    return db[table].count


def _strip_json_keys(row: dict) -> dict:
    """Normalise *_json column names to plain keys for the frontend."""
    out = {}
    for k, v in row.items():
        out[k[:-5] if k.endswith("_json") else k] = v
    return out


# --------------------------------------------------------------------------- app

def create_app() -> FastAPI:
    app = FastAPI(title="Mewtwo", docs_url=None, redoc_url=None, openapi_url=None)
    hub = JobHub()

    # ---- static frontend ----
    @app.get("/")
    async def index():
        return FileResponse(_STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=_STATIC), name="static")

    # ---- read: meta ----
    @app.get("/api/health")
    async def health():
        ws = config.active_workspace()
        return {
            "status": "ok",
            "active_workspace": ws.name if ws else None,
            "ai_configured": bool(config.anthropic_api_key()),
            "auth_configured": any(config.build_auth()[0:2]) if True else False,
        }

    @app.get("/api/workspaces")
    async def workspaces():
        active = config.active_workspace()
        out = []
        for d in sorted(config.workspaces_dir().iterdir()):
            if not d.is_dir():
                continue
            name = d.name
            findings = 0
            db_p = d / "mewtwo.db"
            if db_p.exists():
                try:
                    db = get_db(db_p)
                    findings = _count(db, "findings")
                except Exception:
                    pass
            out.append({
                "slug": name,
                "active": bool(active and active.resolve() == d.resolve()),
                "findings": findings,
            })
        return out

    @app.post("/api/workspaces/{slug}/activate")
    async def activate(slug: str):
        try:
            config.set_active_workspace(slug)
        except FileNotFoundError:
            raise HTTPException(404, f"Workspace '{slug}' not found.")
        return {"active": slug}

    @app.post("/api/workspaces")
    async def create_workspace(req: WorkspaceReq):
        """Create a workspace and set it active — the UI equivalent of `mewtwo init`."""
        from ..utils.validators import slugify
        from ..models.target import Target
        from ..storage.targets import TargetRepository

        name = req.name.strip()
        if not name:
            raise HTTPException(400, "Workspace name is required.")
        slug = slugify(name)
        ws = config.workspace_path(slug)
        if ws.exists():
            config.set_active_workspace(slug)
            return {"slug": slug, "created": False, "active": True}

        ws.mkdir(parents=True, exist_ok=True)
        (ws / "reports").mkdir(exist_ok=True)
        (ws / "evidence").mkdir(exist_ok=True)
        db = get_db(config.db_path(ws))
        target = Target(name=name, slug=slug, platform=req.platform,
                        program_url=req.program_url)
        TargetRepository(db).upsert(target)
        db["targets"].upsert(
            {"id": target.id, "root_domain": req.domain or slug}, pk="id", alter=True)
        config.set_active_workspace(slug)
        return {"slug": slug, "created": True, "active": True}

    @app.get("/api/checks")
    async def checks():
        """Catalog of available hunt checks (for the UI to display/select)."""
        from ..modules.hunt.checks import ALL_CHECKS
        return [{
            "name": c.name, "vuln_class": c.vuln_class, "description": c.description,
            "categories": c.applicable_categories, "aggressive_only": c.aggressive_only,
        } for c in ALL_CHECKS]

    @app.get("/api/status")
    async def status():
        ws, db = _active_db()
        t = _target(db)
        tid = t["id"]
        return {
            "workspace": ws.name,
            "target": {
                "name": t.get("name"),
                "platform": t.get("platform"),
                "program_url": t.get("program_url"),
                "root_domain": t.get("root_domain"),
            },
            "counts": {
                "subdomains": _count(db, "subdomains", "target_id = ?", [tid]),
                "alive": _count(db, "subdomains", "target_id = ? AND is_alive = 1", [tid]),
                "urls": _count(db, "urls", "target_id = ?", [tid]),
                "vectors": _count(db, "attack_vectors", "target_id = ?", [tid]),
                "vectors_checked": _count(db, "attack_vectors", "target_id = ? AND checked = 1", [tid]),
                "findings": _count(db, "findings", "target_id = ?", [tid]),
                "js_secrets": _count(db, "js_secrets", "target_id = ?", [tid]),
            },
        }

    @app.get("/api/scope")
    async def scope():
        ws, db = _active_db()
        tid = _target(db)["id"]
        if "scope" not in db.table_names():
            return []
        return [dict(r) for r in db["scope"].rows_where("target_id = ?", [tid])]

    @app.post("/api/scope")
    async def scope_add(req: ScopeReq):
        ws, db = _active_db()
        tid = _target(db)["id"]
        from ..models.target import ScopeEntry, ScopeType
        from ..storage.targets import ScopeRepository
        type_map = {"in": ScopeType.IN_SCOPE, "out": ScopeType.OUT_OF_SCOPE,
                    "info": ScopeType.INFORMATIONAL}
        if req.scope_type not in type_map:
            raise HTTPException(400, "scope_type must be in/out/info")
        if not req.pattern.strip():
            raise HTTPException(400, "pattern is required")
        ScopeRepository(db).add(ScopeEntry(
            target_id=tid, pattern=req.pattern.strip(),
            scope_type=type_map[req.scope_type], notes=req.notes))
        return {"added": req.pattern}

    @app.delete("/api/scope")
    async def scope_remove(pattern: str):
        ws, db = _active_db()
        tid = _target(db)["id"]
        from ..storage.targets import ScopeRepository
        ScopeRepository(db).remove(tid, pattern)
        return {"removed": pattern}

    # ---- read: data tables ----
    @app.get("/api/subdomains")
    async def subdomains():
        ws, db = _active_db()
        tid = _target(db)["id"]
        if "subdomains" not in db.table_names():
            return []
        rows = db["subdomains"].rows_where("target_id = ?", [tid])
        return [{
            "hostname": r["hostname"],
            "is_alive": bool(r.get("is_alive")),
            "status_code": r.get("status_code"),
        } for r in rows]

    @app.get("/api/urls")
    async def urls(limit: int = 500):
        ws, db = _active_db()
        tid = _target(db)["id"]
        if "urls" not in db.table_names():
            return []
        rows = list(db["urls"].rows_where("target_id = ?", [tid]))[:limit]
        out = []
        for r in rows:
            import json
            params = json.loads(r.get("parameters_json") or "[]")
            out.append({"url": r["url"], "status_code": r.get("status_code"), "params": params})
        return out

    @app.get("/api/vectors")
    async def vectors():
        ws, db = _active_db()
        tid = _target(db)["id"]
        if "attack_vectors" not in db.table_names():
            return []
        rows = db["attack_vectors"].rows_where("target_id = ?", [tid])
        return [{
            "id": r["id"], "category": r["category"], "title": r["title"],
            "url": r["url"], "risk_rating": r.get("risk_rating"),
            "checked": bool(r.get("checked")),
        } for r in rows]

    @app.get("/api/findings")
    async def findings():
        ws, db = _active_db()
        tid = _target(db)["id"]
        if "findings" not in db.table_names():
            return []
        rows = db["findings"].rows_where("target_id = ?", [tid])
        return [{
            "id": r["id"], "title": r["title"], "vuln_class": r.get("vuln_class"),
            "severity": r.get("severity"), "status": r.get("status"), "url": r.get("url"),
            "parameter": r.get("parameter"),
        } for r in rows]

    @app.get("/api/findings/{finding_id}")
    async def finding_detail(finding_id: str):
        ws, db = _active_db()
        rows = list(db["findings"].rows_where("id LIKE ?", [f"{finding_id}%"]))
        if not rows:
            raise HTTPException(404, "Finding not found.")
        import json
        r = dict(rows[0])
        for k in ("evidence_json", "reproduction_steps_json", "references_json",
                  "tags_json", "cvss_json"):
            if k in r and r[k]:
                try:
                    r[k] = json.loads(r[k])
                except (json.JSONDecodeError, TypeError):
                    pass
        return _strip_json_keys(r)

    # ---- actions: jobs ----
    @app.get("/api/jobs")
    async def jobs_state():
        return hub.state

    @app.post("/api/jobs/recon")
    async def start_recon(req: ReconReq):
        ws, db = _active_db()
        t = _target(db)
        from ..models.target import Target
        from ..modules.recon.runner import run_full_recon, clear_checkpoints

        target = Target(id=t["id"], name=t["name"], slug=t["slug"],
                        platform=t.get("platform", ""))
        root = t.get("root_domain") or t["slug"]
        scope_rows = list(db["scope"].rows_where(
            "target_id = ? AND scope_type = 'in_scope'", [t["id"]]))
        patterns = [r["pattern"] for r in scope_rows] or [f"*.{root}", root]
        if req.force:
            clear_checkpoints(db, t["id"])

        def factory(progress):
            return run_full_recon(
                target=target, db_path=config.db_path(ws), scope_patterns=patterns,
                steps=set(req.steps) if req.steps else None,
                passive_only=req.passive_only, use_ai=False,
                resume=not req.force, on_progress=progress,
            )

        try:
            hub.start("recon", factory)
        except RuntimeError as e:
            raise HTTPException(409, str(e))
        return {"started": "recon"}

    @app.post("/api/jobs/surface")
    async def start_surface():
        ws, db = _active_db()
        t = _target(db)
        from ..modules.surface.mapper import run_surface_map

        def factory(progress):
            async def _run():
                progress({"phase": "surface", "detail": "mapping heuristics"})
                vectors = await run_surface_map(t["id"], config.db_path(ws), use_ai=False)
                return {"vectors": len(vectors)}
            return _run()

        try:
            hub.start("surface", factory)
        except RuntimeError as e:
            raise HTTPException(409, str(e))
        return {"started": "surface"}

    @app.post("/api/jobs/hunt")
    async def start_hunt(req: HuntReq):
        ws, db = _active_db()
        t = _target(db)
        from ..modules.hunt.runner import run_hunt
        from ..modules.hunt.safety import SafetyTier

        scope_rows = list(db["scope"].rows_where(
            "target_id = ? AND scope_type = 'in_scope'", [t["id"]]))
        patterns = [r["pattern"] for r in scope_rows]
        # Auth is read from the server environment only — never from the browser.
        auth = config.build_auth() if req.use_auth else ({}, {})

        def factory(progress):
            async def _run():
                fs = await run_hunt(
                    target_id=t["id"], db_path=config.db_path(ws),
                    evidence_dir=config.evidence_dir(ws),
                    use_ai=False, tier=SafetyTier(req.tier),
                    scope_patterns=patterns, rate=req.rate, auth=auth,
                    enforce_scope=req.enforce_scope, on_progress=progress,
                )
                return {"findings": len(fs)}
            return _run()

        try:
            hub.start("hunt", factory)
        except RuntimeError as e:
            raise HTTPException(409, str(e))
        return {"started": "hunt"}

    # ---- websocket: live job progress ----
    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()
        q = hub.subscribe()
        try:
            while True:
                event = await q.get()
                await ws.send_json(event)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            hub.unsubscribe(q)

    return app
