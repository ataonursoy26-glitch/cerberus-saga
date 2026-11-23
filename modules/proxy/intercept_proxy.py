"""
modules/proxy/intercept_proxy.py
Intercepting HTTP proxy (Burp Suite / mitmproxy style — lightweight version).

The user points THEIR OWN browser at this proxy (e.g. 127.0.0.1:8081);
the proxy records outgoing requests and incoming responses and shows them in the dashboard.
It also runs DLP (PII/secret) scanning on the HTTP response bodies that pass through
and raises a "sensitive data is flowing in this traffic" warning.

ETHICS/SCOPE BOUNDARY:
  * This is a local tool for the user to inspect THEIR OWN traffic
    (authorized self-testing). It does not intercept other people's traffic on the network.
  * HTTPS requests are only TUNNELED (CONNECT); content is NOT decrypted
    (NO MITM with a fake CA). Only the destination host:port is recorded.
"""
from __future__ import annotations

import logging
import select
import socket
import threading
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

log = logging.getLogger("cerberus.proxy")

_TX: "deque[dict]" = deque(maxlen=500)
_LOCK = threading.Lock()


def transactions(limit: int = 100) -> list[dict]:
    with _LOCK:
        return list(_TX)[-limit:][::-1]


def clear() -> None:
    with _LOCK:
        _TX.clear()


def _record(tx: dict) -> None:
    with _LOCK:
        _TX.append(tx)


def _dlp_scan(body: str) -> list[str]:
    """Is there sensitive data in the passing body? (returns a masked category list)"""
    try:
        from modules.dlp.pii_spii_scanner import PIISPIIScanner
        rep = PIISPIIScanner().scan_text(body[:50000], "proxy")
        return sorted({f.category for f in rep.findings if f.severity != "INFO"})
    except Exception:  # noqa: BLE001
        return []


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 15

    def log_message(self, *a):  # sessiz
        pass

    # --- HTTPS: CONNECT tunnel (NO decryption) ----------------------------
    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc)[:80])
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        _record({"time": ts, "method": "CONNECT", "host": host, "port": port,
                 "scheme": "https", "status": "tunnel", "note": "HTTPS tunneled (not decrypted)",
                 "dlp": []})
        self._tunnel(self.connection, upstream)

    def _tunnel(self, a: socket.socket, b: socket.socket) -> None:
        socks = [a, b]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 10)
                if x or not r:
                    break
                for s in r:
                    data = s.recv(8192)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except Exception:  # noqa: BLE001
            pass
        finally:
            for s in socks:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass

    # --- HTTP: all methods ------------------------------------------------
    def _proxy(self):
        url = self.path
        parts = urlsplit(url)
        host = parts.hostname or self.headers.get("Host", "")
        port = parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        ts = datetime.now().strftime("%H:%M:%S")

        length = int(self.headers.get("Content-Length", "0") or 0)
        req_body = self.rfile.read(length) if length else b""

        # Forward the request to the upstream server
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc)[:80])
            return
        req_lines = [f"{self.command} {path} HTTP/1.1"]
        for k, v in self.headers.items():
            if k.lower() in ("proxy-connection",):
                continue
            req_lines.append(f"{k}: {v}")
        req_lines.append("Connection: close")
        raw = ("\r\n".join(req_lines) + "\r\n\r\n").encode() + req_body
        upstream.sendall(raw)

        resp = b""
        try:
            while len(resp) < 500_000:
                chunk = upstream.recv(8192)
                if not chunk:
                    break
                resp += chunk
        except Exception:  # noqa: BLE001
            pass
        finally:
            upstream.close()

        # Send the response back to the client as-is
        try:
            self.connection.sendall(resp)
        except Exception:  # noqa: BLE001
            pass

        text = resp.decode("utf-8", "ignore")
        status = ""
        if text.startswith("HTTP/"):
            status = " ".join(text.split("\r\n", 1)[0].split(" ")[1:3])
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        _record({"time": ts, "method": self.command, "host": host, "port": port,
                 "scheme": "http", "path": path, "status": status,
                 "resp_bytes": len(resp), "dlp": _dlp_scan(body)})

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _proxy


class ProxyManager:
    def __init__(self) -> None:
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def is_running(self) -> bool:
        return self._httpd is not None

    def start(self, port: int = 8081, host: str = "127.0.0.1") -> dict:
        if self.is_running():
            return {"ok": True, "port": self.port, "note": "Proxy is already running."}
        try:
            self._httpd = ThreadingHTTPServer((host, port), _ProxyHandler)
        except OSError as exc:
            return {"ok": False, "error": f"Could not open port {port}: {exc}"}
        self.port = port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        log.info("Intercepting proxy started: %s:%d", host, port)
        return {"ok": True, "port": port,
                "note": f"Set your browser proxy to {host}:{port}, then browse."}

    def stop(self) -> dict:
        if not self.is_running():
            return {"ok": True, "note": "Proxy is already stopped."}
        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        log.info("Proxy durduruldu.")
        return {"ok": True, "note": "Proxy durduruldu."}


manager = ProxyManager()
