"""
modules/iam/_http.py
Small, fault-tolerant asynchronous HTTP helper for the IAM modules.
Does not crash without network access or when the target is down; returns status_code=0.
Used only on targets that passed the authorization gate.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass
class Response:
    status_code: int
    text: str


class SafeHTTPClient:
    async def _request(self, method: str, url: str, **kwargs) -> Response:
        host = url.split("://")[-1].split("/")[0].split(":")[0]
        port = 443 if url.startswith("https") else 80
        path = "/" + url.split("://")[-1].split("/", 1)[1] if "/" in url.split("://")[-1] else "/"
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0)
            req = f"{method} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            writer.close()
            raw = data.decode(errors="ignore")
            status = 0
            if raw.startswith("HTTP/"):
                try:
                    status = int(raw.split(" ")[1])
                except (IndexError, ValueError):
                    status = 0
            return Response(status_code=status, text=raw)
        except Exception:  # noqa: BLE001
            return Response(status_code=0, text="")

    async def get(self, url: str, **kwargs) -> Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self._request("POST", url, **kwargs)
