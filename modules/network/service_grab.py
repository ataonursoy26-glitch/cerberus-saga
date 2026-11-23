"""
modules/network/service_grab.py
Banner grabbing and protocol/version analysis (Blueprint Volume 1, network).

Extracts the service version on an open port by collecting HTTP/TLS
handshake headers. Reads headers only; never attempts an exploit.
"""
from __future__ import annotations

import asyncio
import logging

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.grab")


class ServiceGrabber:
    async def grab(self, target: str, port: int = 80) -> dict:
        assert_in_scope(target)
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0
            )
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            headers = data.decode(errors="ignore")
            server = next(
                (l.split(":", 1)[1].strip() for l in headers.splitlines()
                 if l.lower().startswith("server:")), "unknown"
            )
            return {"port": port, "server": server, "raw_headers": headers[:500]}
        except Exception as exc:  # noqa: BLE001
            return {"port": port, "error": str(exc)[:80]}
