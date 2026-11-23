"""
modules/network/port_scanner.py
Subprocess-based asynchronous Nmap port/service scanner (Blueprint Volume 3, Module 2).

If the nmap binary is installed it runs a real -sV scan and parses the XML output.
Otherwise it falls back to a basic TCP connect scan using Python's own
asyncio sockets — so the demo also works without external binaries.
Every call goes through the authorization gate.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import xml.etree.ElementTree as ET

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.net")

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8000, 8080, 8443]


class NetworkScanner:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target.split("://")[-1].split("/")[0].split(":")[0]
        self.output_file = f"storage/raw_logs/{self.target}_nmap.xml"

    async def scan_ports(self) -> dict:
        if shutil.which("nmap"):
            return await self._nmap_scan()
        log.warning("nmap not found -> falling back to the built-in TCP connect scan.")
        return await self._fallback_scan()

    async def _nmap_scan(self) -> dict:
        os.makedirs("storage/raw_logs", exist_ok=True)
        cmd = f"nmap -sV -F -T4 -oX {self.output_file} {self.target}"
        log.info("Running Nmap: %s", cmd)
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        return self._parse_xml()

    def _parse_xml(self) -> dict:
        ports, banners = [], []
        if not os.path.exists(self.output_file):
            return {"ports": ports, "banners": banners, "engine": "nmap"}
        try:
            root = ET.parse(self.output_file).getroot()
            for host in root.findall("host"):
                for p in host.findall("ports/port"):
                    state = p.find("state")
                    if state is not None and state.get("state") == "open":
                        svc = p.find("service")
                        name = svc.get("name") if svc is not None else "unknown"
                        product = svc.get("product", "") if svc is not None else ""
                        version = svc.get("version", "") if svc is not None else ""
                        ports.append({"port": p.get("portid"), "service": name,
                                      "product": product, "version": version})
                        banners.append(f"{name} {product} {version}".strip())
        except Exception as exc:  # noqa: BLE001
            log.warning("Nmap XML parse error: %s", exc)
        return {"ports": ports, "banners": banners, "engine": "nmap"}

    async def _fallback_scan(self) -> dict:
        ports: list[dict] = []

        async def probe(port: int) -> None:
            try:
                fut = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.0)
                ports.append({"port": str(port), "service": "open", "product": "", "version": ""})
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass

        await asyncio.gather(*(probe(p) for p in COMMON_PORTS))
        log.info("Fallback scan: %d open ports.", len(ports))
        return {"ports": ports, "banners": [], "engine": "tcp-connect-fallback"}
