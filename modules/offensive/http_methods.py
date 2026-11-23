"""
modules/offensive/http_methods.py
HTTP method abuse detection (authorized, non-destructive).

Inspects which HTTP methods the server allows (OPTIONS/Allow) and
flags the risky ones:
  * TRACE/TRACK -> Cross-Site Tracing (XST), cookie-theft surface
  * PUT / DELETE -> unauthorized file write/delete surface (reported only if ADVERTISED)
  * CONNECT -> proxy abuse
NON-DESTRUCTIVE: it never actually attempts PUT/DELETE (writes/deletes nothing); it only
reads the methods advertised via OPTIONS and safely tests TRACE.
Only on in-scope targets.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.methods")

RISKY = {
    "TRACE": ("HIGH", "TRACE enabled — Cross-Site Tracing (XST) / cookie exposure risk."),
    "TRACK": ("HIGH", "TRACK enabled — TRACE-like XST risk."),
    "PUT": ("MEDIUM", "PUT advertised — possible unauthorized file-upload surface (verify)."),
    "DELETE": ("MEDIUM", "DELETE advertised — possible unauthorized resource-deletion surface."),
    "CONNECT": ("MEDIUM", "CONNECT advertised — proxy abuse risk."),
    "PATCH": ("LOW", "PATCH advertised — modification surface."),
}


@dataclass
class MethodFinding:
    severity: str
    detail: str


@dataclass
class MethodReport:
    target: str
    allow: str = ""
    findings: list = field(default_factory=list)


class HTTPMethodTester:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> MethodReport:
        rep = MethodReport(target=self.target)
        opt = request(self.target, method="OPTIONS")
        allow = opt.headers.get("allow", "")
        rep.allow = allow
        for m, (sev, msg) in RISKY.items():
            if m in allow.upper():
                rep.findings.append(MethodFinding(sev, msg))

        # safely test TRACE (non-destructive): if it reflects, XST is confirmed
        tr = request(self.target, method="TRACE")
        if tr.status == 200 and ("TRACE" in (tr.body or "")[:200].upper()):
            rep.findings.append(MethodFinding("HIGH",
                "TRACE request was echoed (XST confirmed) — browser-based cookie theft is possible."))

        if not rep.findings:
            rep.findings.append(MethodFinding("INFO",
                f"No risky method advertised (Allow: {allow or 'unknown'})."))
        log.info("HTTP method test (%s): Allow=%s, %d findings.", self.target, allow, len(rep.findings))
        return rep
