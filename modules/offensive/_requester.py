"""
modules/offensive/_requester.py
Shared, fault-tolerant HTTP(S) requester for the offensive modules.
GET-only, does not follow redirects, read-only. Authorization is checked by the caller.
"""
from __future__ import annotations

import http.client
import os
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

# Global polite rate limit: wait at least this long (seconds) between requests
# in the same session, to avoid overloading the target or triggering 429/WAF. Set via ENV.
_MIN_INTERVAL = float(os.getenv("CERBERUS_REQ_INTERVAL", "0.3"))
_last_lock = threading.Lock()
_last_ts = [0.0]


def _throttle() -> None:
    with _last_lock:
        now = time.monotonic()
        wait = _MIN_INTERVAL - (now - _last_ts[0])
        if wait > 0:
            time.sleep(wait)
        _last_ts[0] = time.monotonic()


@dataclass
class Resp:
    status: int
    headers: dict
    body: str
    error: str = ""


UA = "Cerberus-Security-Scanner/1.0 (+authorized-pentest)"


def request(url: str, method: str = "GET", timeout: int = 8, read_bytes: int = 120_000,
            extra_headers: dict | None = None, body: str | None = None) -> Resp:
    parts = urlsplit(url if "://" in url else "http://" + url)
    https = parts.scheme == "https"
    host = parts.hostname
    port = parts.port or (443 if https else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if extra_headers:
        hdrs.update(extra_headers)
    _throttle()  # polite rate limit
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, body=body.encode() if body else None, headers=hdrs)
        r = conn.getresponse()
        body = r.read(read_bytes).decode("utf-8", "ignore") if method != "HEAD" else ""
        headers = {k.lower(): v for k, v in r.getheaders()}
        status = r.status
        conn.close()
        return Resp(status=status, headers=headers, body=body)
    except Exception as exc:  # noqa: BLE001
        return Resp(status=0, headers={}, body="", error=str(exc)[:80])
