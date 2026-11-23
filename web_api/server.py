"""
web_api/server.py
Zero-dependency web interface (Python stdlib http.server).

Goal: make the tool easy to use even for someone who does not know the CLI.
  * GET  /            -> easy-to-use control panel (single page)
  * GET  /api/scope   -> targets within the authorization scope
  * POST /api/scan    -> {"target": "..."} -> runs the scan, JSON result
  * GET  /reports/... -> the generated HTML report

No pip install required. Run:  python3 cerberus.py serve
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from config.settings import get_authorized_scope
from core.orchestrator import CerberusOrchestrator
from core.scope_guard import is_in_scope
from modules.network import interfaces as ifaces_mod
from modules.network import connection_monitor as conn_mod
from modules.network import packet_capture as pcap_mod
from modules.proxy.intercept_proxy import manager as proxy_manager, transactions as proxy_tx, clear as proxy_clear
from modules.web.storefront_audit import StorefrontAuditor

log = logging.getLogger("cerberus.web")
BASE = Path(__file__).resolve().parent.parent


def to_jsonable(obj):
    """Makes dataclass / report objects JSON-serializable."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def run_scan(target: str, demo_blob: str | None = None) -> dict:
    results = asyncio.run(CerberusOrchestrator(target, demo_blob=demo_blob).run_pipeline())
    return to_jsonable(results)


INDEX_HTML = (BASE / "web_api" / "index.html").read_text(encoding="utf-8") \
    if (BASE / "web_api" / "index.html").exists() else "<h1>index.html missing</h1>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # sessiz log
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/scope":
            self._json(200, {"scope": get_authorized_scope()})
        elif self.path == "/api/interfaces":
            self._json(200, {"interfaces": ifaces_mod.list_interfaces(),
                             "gateway": ifaces_mod.default_gateway(),
                             "neighbors": ifaces_mod.local_subnet_hosts().get("neighbors", [])})
        elif self.path == "/api/connections":
            self._json(200, conn_mod.snapshot(established_only=False, limit=150))
        elif self.path == "/api/proxy/status":
            self._json(200, {"running": proxy_manager.is_running(), "port": proxy_manager.port})
        elif self.path == "/api/proxy/tx":
            self._json(200, {"transactions": proxy_tx(150)})
        elif self.path.startswith("/api/history"):
            from urllib.parse import urlsplit, parse_qs
            from modules.posture import list_snapshots
            q = parse_qs(urlsplit(self.path).query)
            target = (q.get("target", [""])[0]).strip()
            snaps = list_snapshots(target) if target else []
            self._json(200, {"history": [{"ts": s["ts"], "score": s["score"],
                                          "grade": s["grade"]} for s in snaps]})
        elif self.path.startswith("/reports/"):
            name = self.path.split("/reports/", 1)[1].split("?")[0]
            p = BASE / "reports" / name
            if ".." in name or not p.exists():
                self._json(404, {"error": "Report not found"})
            else:
                self._send(200, p.read_bytes(), "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})
            return

        if self.path == "/api/jwt":
            tok = (payload.get("token") or "").strip()
            if not tok:
                self._json(400, {"error": "token required"})
                return
            from modules.offensive.jwt_analyzer import JWTAnalyzer
            rep = JWTAnalyzer().analyze(tok)
            self._json(200, {"ok": True, "header": rep.header, "payload": rep.payload,
                             "cracked_secret": rep.cracked_secret,
                             "findings": [{"check": f.check, "severity": f.severity, "detail": f.detail}
                                          for f in rep.findings]})
            return

        if self.path == "/api/assess":
            target = (payload.get("target") or "").strip()
            if not target:
                self._json(400, {"error": "target required"})
                return
            if not is_in_scope(target):
                self._json(403, {"error": f"'{target}' is outside the authorization scope. "
                                          "Must be verified via verify-ownership."})
                return
            try:
                from utils.assessment_report import collect, build
                from modules.posture import score_findings, save_snapshot
                from modules.offensive._requester import request as _req
                pre = _req(target, timeout=8)
                if pre.status in (429, 403, 503) or pre.status == 0:
                    self._json(200, {"ok": True, "inconclusive": True, "target": target,
                                     "note": f"Target returned HTTP {pre.status} (rate-limit/WAF likely). "
                                             "Assessment deferred to avoid a fake grade."})
                    return
                stack, sections = collect(target)
                path = build(target, sections, stack)
                score, grade, counts = score_findings(sections)
                save_snapshot(target, sections, stack)
                total = sum(len(s["findings"]) for s in sections)
                self._json(200, {"ok": True, "target": target, "stack": stack,
                                 "sections": sections, "total": total,
                                 "score": score, "grade": grade, "counts": counts,
                                 "report": Path(path).name})
            except Exception as exc:  # noqa: BLE001
                self._json(500, {"error": str(exc)[:160]})
            return

        if self.path == "/api/storefront":
            target = (payload.get("target") or "").strip()
            if not target:
                self._json(400, {"error": "target required"})
                return
            if not is_in_scope(target):
                self._json(403, {"error": f"'{target}' is outside the authorization scope."})
                return
            try:
                from modules.web.tls_analyzer import TLSAnalyzer
                from modules.web.email_security import EmailSecurityAuditor
                rep = StorefrontAuditor(target).audit()
                findings = [{"area": f.area, "severity": f.severity, "detail": f.detail}
                            for f in rep.findings]
                # TLS
                tls = TLSAnalyzer(target).analyze()
                for f in tls.findings:
                    findings.append({"area": "TLS", "severity": f.severity, "detail": f.detail})
                tls_info = tls.info
                # Email security
                email = EmailSecurityAuditor().audit(target)
                for f in email.findings:
                    findings.append({"area": "E-posta", "severity": f.severity, "detail": f.detail})
                order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
                findings.sort(key=lambda x: order.get(x["severity"], 9))
                self._json(200, {"ok": True, "target": rep.target, "findings": findings,
                                 "trust_pages": rep.trust_pages, "tls": tls_info,
                                 "email": email.records})
            except Exception as exc:  # noqa: BLE001
                self._json(500, {"error": str(exc)[:160]})
            return

        if self.path == "/api/capture":
            iface = (payload.get("interface") or "").strip()
            if not iface:
                self._json(400, {"error": "interface is required"})
                return
            self._json(200, pcap_mod.capture(
                iface, count=int(payload.get("count", 20)),
                bpf_filter=payload.get("filter", ""), timeout=int(payload.get("timeout", 20))))
            return
        if self.path == "/api/proxy/start":
            self._json(200, proxy_manager.start(int(payload.get("port", 8081))))
            return
        if self.path == "/api/proxy/stop":
            self._json(200, proxy_manager.stop())
            return
        if self.path == "/api/proxy/clear":
            proxy_clear()
            self._json(200, {"ok": True})
            return

        if self.path != "/api/scan":
            self._json(404, {"error": "not found"})
            return
        target = (payload.get("target") or "").strip()
        demo = payload.get("demo", False)
        if not target:
            self._json(400, {"error": "target required"})
            return
        if not is_in_scope(target):
            self._json(403, {"error": f"'{target}' is outside the authorization scope. "
                                      "Select a target from scope.yaml."})
            return
        try:
            blob = None
            if demo:
                blob = (BASE / "tests/fixtures/leaky_response.txt").read_text(encoding="utf-8")
            results = run_scan(target, demo_blob=blob)
            report = results.get("report_path", "")
            report_name = Path(report).name if report else ""
            self._json(200, {"ok": True, "report": report_name, "results": results})
        except PermissionError as exc:
            self._json(403, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            log.exception("scan error")
            self._json(500, {"error": f"scan error: {exc}"})


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"\n  🛡️  Cerberus web dashboard: {url}\n  (Ctrl+C to stop)\n")
    if open_browser:
        threading.Timer(1.0, lambda: __import__("webbrowser").open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
        httpd.shutdown()
