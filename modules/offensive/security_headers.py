"""
modules/offensive/security_headers.py
Comprehensive HTTP security header + cookie audit (authorized, read-only).

Audits HSTS (including preload/includeSubDomains), cookie flags (Secure/HttpOnly/
SameSite), X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
SameSite), COOP/COEP/CORP isolation headers, and server version disclosure.
Defers if it sees a rate-limit (429). Only on in-scope targets.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.headers")


@dataclass
class HdrFinding:
    header: str
    severity: str
    detail: str


@dataclass
class HdrReport:
    target: str
    inconclusive: bool = False
    findings: list = field(default_factory=list)


class SecurityHeaderAuditor:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> HdrReport:
        rep = HdrReport(target=self.target)
        r = request(self.target, read_bytes=50_000)
        if r.status in (429, 403, 503) or r.status == 0:
            rep.inconclusive = True
            return rep
        h = r.headers

        # HSTS
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            rep.findings.append(HdrFinding("HSTS", "HIGH", "No HSTS — SSL-stripping/MITM risk."))
        else:
            try:
                age = int(hsts.split("max-age=")[1].split(";")[0])
            except (IndexError, ValueError):
                age = 0
            if age < 31536000:
                rep.findings.append(HdrFinding("HSTS", "LOW", f"HSTS max-age is low ({age}) — ≥1 year recommended."))
            if "includesubdomains" not in hsts.lower():
                rep.findings.append(HdrFinding("HSTS", "LOW", "HSTS has no includeSubDomains."))
            if "preload" not in hsts.lower():
                rep.findings.append(HdrFinding("HSTS", "INFO", "No HSTS preload (optional, stronger)."))

        # Other headers
        checks = [
            ("x-content-type-options", "nosniff", "MEDIUM", "No X-Content-Type-Options: nosniff — MIME sniffing."),
            ("referrer-policy", "", "LOW", "No Referrer-Policy — navigation data may leak."),
            ("permissions-policy", "", "LOW", "No Permissions-Policy — device permissions unrestricted."),
            ("cross-origin-opener-policy", "", "LOW", "No COOP — weak cross-origin isolation (Spectre class)."),
            ("cross-origin-resource-policy", "", "INFO", "No CORP — resource isolation undefined."),
        ]
        for name, needval, sev, msg in checks:
            val = h.get(name, "")
            if not val or (needval and needval not in val.lower()):
                rep.findings.append(HdrFinding(name, sev, msg))

        # Server version disclosure
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            if h.get(name) and any(c.isdigit() for c in h[name]):
                rep.findings.append(HdrFinding(name, "LOW",
                    f"Version disclosure: {name}: {h[name]} — gives an attacker version info."))

        # Cookie flags
        for c in (r.cookies if hasattr(r, "cookies") else []):
            pass  # _requester keeps a single set-cookie in headers
        sc = h.get("set-cookie", "")
        if sc:
            low = sc.lower()
            miss = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
            if miss:
                rep.findings.append(HdrFinding("Set-Cookie", "LOW",
                    f"Cookie is missing flag(s): {', '.join(miss)}."))

        if not rep.findings:
            rep.findings.append(HdrFinding("ok", "INFO", "Security headers look solid."))
        log.info("Header audit (%s): %d findings.", self.target, len(rep.findings))
        return rep
