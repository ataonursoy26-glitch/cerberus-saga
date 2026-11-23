"""
modules/network/content_fetch.py
Real HTTP content-fetching layer (for live scans).

Downloads the target's REAL HTTP response body so the DLP / OWASP / AI
injection modules analyze live content instead of simulated data.
Runs only on in-scope targets. Never modifies content; read-only.
"""
from __future__ import annotations

import asyncio
import logging
import ssl

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.fetch")

MAX_BYTES = 200_000
PATHS = ["/", "/robots.txt", "/.git/config", "/config.php", "/login"]


class ContentFetcher:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        raw = target.split("://")[-1]
        self.host = raw.split("/")[0].split(":")[0]
        self.https = target.startswith("https")

    async def _fetch_one(self, path: str) -> dict | None:
        port = 443 if self.https else 80
        try:
            if self.https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, port, ssl=ctx), timeout=5.0)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, port), timeout=5.0)
            req = (f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\n"
                   f"User-Agent: Cerberus-Security-Scanner/1.0 (+authorized-pentest)\r\n"
                   f"Accept: */*\r\nConnection: close\r\n\r\n")
            writer.write(req.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(MAX_BYTES), timeout=6.0)
            writer.close()
            text = data.decode(errors="ignore")
            status = 0
            if text.startswith("HTTP/"):
                try:
                    status = int(text.split(" ", 2)[1])
                except (IndexError, ValueError):
                    status = 0
            return {"path": path, "status": status, "body": text}
        except Exception as exc:  # noqa: BLE001
            log.debug("fetch %s failed: %s", path, str(exc)[:60])
            return None

    async def fetch(self) -> dict:
        results = await asyncio.gather(*(self._fetch_one(p) for p in PATHS))
        pages = [r for r in results if r]
        bodies = [p["body"] for p in pages]
        log.info("Content fetch: %d/%d pages downloaded (%d bytes).",
                 len(pages), len(PATHS), sum(len(b) for b in bodies))
        return {"pages": pages, "bodies": bodies}
