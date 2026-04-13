"""Attack surface mapper — combines heuristics + AI expansion."""

from __future__ import annotations

from pathlib import Path

from ...db import get_db
from ...models.surface import AttackVector, VectorCategory
from ...storage.recon import ReconRepository
from ...storage.surface import SurfaceRepository
from ...utils.console import info, success
from .heuristics import map_from_recon


async def run_surface_map(
    target_id: str,
    db_path: Path,
    use_ai: bool = True,
) -> list[AttackVector]:
    """Map attack surface from recon data. Optionally expand with AI."""
    db = get_db(db_path)
    recon = ReconRepository(db)
    surf = SurfaceRepository(db)

    urls = recon.urls_for(target_id)
    techs = recon.techs_for(target_id)
    secrets = recon.js_secrets_for(target_id)
    subs = recon.subdomains_for(target_id)

    info("Running heuristic surface mapping...")
    vectors = map_from_recon(target_id, urls, techs, secrets, subs)
    success(f"Heuristics identified {len(vectors)} attack vector(s)")

    if use_ai:
        try:
            from ...modules.ai.client import AIClient
            client = AIClient()
            info("Expanding attack surface with AI...")
            recon_summary = {
                "subdomain_count": len(subs),
                "alive_subdomains": [s["hostname"] for s in subs if s.get("is_alive")][:20],
                "url_count": len(urls),
                "sample_urls": [u["url"] for u in urls[:20]],
                "technologies": [t["name"] for t in techs],
                "js_secret_types": list({s["secret_type"] for s in secrets}),
            }
            existing = [{"category": v.category, "title": v.title, "url": v.url} for v in vectors]
            result = client.expand_attack_surface(recon_summary, existing, db_path)
            ai_vectors_data = result.get("vectors", [])
            ai_vectors = []
            for vd in ai_vectors_data:
                try:
                    av = AttackVector(
                        target_id=target_id,
                        category=VectorCategory(vd["category"]),
                        title=vd["title"],
                        description=vd["description"],
                        url=vd["url"],
                        parameters=vd.get("parameters", []),
                        risk_rating=vd.get("risk_rating", "medium"),
                        rationale=vd.get("rationale", ""),
                    )
                    ai_vectors.append(av)
                except Exception:
                    continue
            vectors.extend(ai_vectors)
            success(f"AI added {len(ai_vectors)} additional vector(s)")
        except Exception as e:
            info(f"AI expansion skipped: {e}")

    for v in vectors:
        surf.upsert(v)

    return vectors
