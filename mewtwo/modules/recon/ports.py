"""Port and service discovery via nmap (subprocess wrapper)."""

from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET

from ...models.recon import Port
from ...utils.console import info, warn
from ...utils.process import run, tool_available


async def scan_ports(
    target_id: str,
    host: str,
    top_ports: int = 1000,
) -> list[Port]:
    """Run nmap against host, return Port models."""
    if not tool_available("nmap"):
        warn("nmap not found — skipping port scan. Install nmap for this feature.")
        return []

    info(f"Port scanning {host} (top {top_ports})...")
    try:
        _, stdout, _ = await run(
            "nmap",
            "-sV",
            f"--top-ports={top_ports}",
            "-oX", "-",   # XML output to stdout
            "--open",
            "-T4",
            host,
            timeout=300,
        )
        return _parse_nmap_xml(target_id, host, stdout)
    except Exception as e:
        warn(f"nmap scan failed for {host}: {e}")
        return []


def _parse_nmap_xml(target_id: str, host: str, xml_output: str) -> list[Port]:
    ports: list[Port] = []
    try:
        root = ET.fromstring(xml_output)
        for port_elem in root.findall(".//port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_elem.find("service")
            ports.append(Port(
                id=str(uuid.uuid4()),
                target_id=target_id,
                host=host,
                port=int(port_elem.get("portid", 0)),
                protocol=port_elem.get("protocol", "tcp"),
                service=service.get("name", "") if service is not None else "",
                version=(
                    f"{service.get('product', '')} {service.get('version', '')}".strip()
                    if service is not None else ""
                ),
                banner=service.get("extrainfo", "") if service is not None else "",
            ))
    except ET.ParseError:
        pass
    return ports
