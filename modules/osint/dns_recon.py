"""
modules/osint/dns_recon.py
Asynchronous DNS recon / subdomain inventory (Blueprint Volume 1, OSINT).

Performs passive DNS resolution only (queries common subdomains).
No aggressive brute-forcing; subject to the authorization gate.
"""
from __future__ import annotations

import asyncio
import logging
import socket

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.dns")

COMMON_SUBDOMAINS = ["www", "mail", "api", "dev", "staging", "admin", "vpn", "test"]


class DNSRecon:
    async def enumerate(self, target: str) -> dict:
        assert_in_scope(target)
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        found = []

        async def resolve(name: str) -> None:
            try:
                loop = asyncio.get_running_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, name)
                found.append({"name": name, "ip": ip})
            except Exception:  # noqa: BLE001
                pass

        base = host.split(".", 1)[-1] if host.count(".") >= 1 else host
        candidates = [host] + [f"{s}.{base}" for s in COMMON_SUBDOMAINS]
        await asyncio.gather(*(resolve(c) for c in dict.fromkeys(candidates)))
        log.info("DNS recon: %d records resolved.", len(found))
        return {"resolved": found, "count": len(found)}
