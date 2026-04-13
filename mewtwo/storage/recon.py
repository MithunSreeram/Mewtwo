from __future__ import annotations

import json

from ..models.recon import Subdomain, Port, Technology, DiscoveredURL, JSSecret
from .base import BaseRepository, _ser


class ReconRepository(BaseRepository):
    table_name = "subdomains"

    # ----- Subdomains -----

    def upsert_subdomain(self, sub: Subdomain) -> None:
        self.db["subdomains"].upsert({
            "id": sub.id,
            "target_id": sub.target_id,
            "hostname": sub.hostname,
            "ip_addresses_json": json.dumps(sub.ip_addresses),
            "sources_json": json.dumps(sub.sources),
            "is_alive": int(sub.is_alive),
            "status_code": sub.status_code,
            "discovered_at": _ser(sub.discovered_at),
        }, pk="id", alter=True)

    def subdomains_for(self, target_id: str) -> list[dict]:
        return [
            {**dict(r),
             "ip_addresses": json.loads(r["ip_addresses_json"] or "[]"),
             "sources": json.loads(r["sources_json"] or "[]"),
             "is_alive": bool(r["is_alive"])}
            for r in self.db["subdomains"].rows_where("target_id = ?", [target_id])
        ]

    # ----- Ports -----

    def upsert_port(self, port: Port) -> None:
        self.db["ports"].upsert({
            "id": port.id,
            "target_id": port.target_id,
            "host": port.host,
            "port": port.port,
            "protocol": port.protocol,
            "service": port.service,
            "version": port.version,
            "banner": port.banner,
        }, pk="id")

    def ports_for(self, target_id: str) -> list[dict]:
        return [dict(r) for r in self.db["ports"].rows_where("target_id = ?", [target_id])]

    # ----- Technologies -----

    def upsert_tech(self, tech: Technology) -> None:
        self.db["technologies"].upsert({
            "id": tech.id,
            "target_id": tech.target_id,
            "host": tech.host,
            "name": tech.name,
            "version": tech.version,
            "category": tech.category,
            "confidence": tech.confidence,
        }, pk="id")

    def techs_for(self, target_id: str) -> list[dict]:
        return [dict(r) for r in self.db["technologies"].rows_where("target_id = ?", [target_id])]

    # ----- URLs -----

    def upsert_url(self, url: DiscoveredURL) -> None:
        self.db["urls"].upsert({
            "id": url.id,
            "target_id": url.target_id,
            "url": url.url,
            "method": url.method,
            "status_code": url.status_code,
            "content_type": url.content_type,
            "parameters_json": json.dumps(url.parameters),
            "forms_json": json.dumps(url.forms),
            "interesting_headers_json": json.dumps(url.interesting_headers),
        }, pk="id")

    def urls_for(self, target_id: str) -> list[dict]:
        return [
            {**dict(r),
             "parameters": json.loads(r["parameters_json"] or "[]"),
             "forms": json.loads(r["forms_json"] or "[]"),
             "interesting_headers": json.loads(r["interesting_headers_json"] or "{}")}
            for r in self.db["urls"].rows_where("target_id = ?", [target_id])
        ]

    # ----- JS Secrets -----

    def upsert_js_secret(self, secret: JSSecret) -> None:
        self.db["js_secrets"].upsert({
            "id": secret.id,
            "target_id": secret.target_id,
            "source_url": secret.source_url,
            "secret_type": secret.secret_type,
            "value": secret.value,
            "confidence": secret.confidence,
        }, pk="id")

    def js_secrets_for(self, target_id: str) -> list[dict]:
        return [dict(r) for r in self.db["js_secrets"].rows_where("target_id = ?", [target_id])]
