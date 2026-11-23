"""
modules/offensive/csp_analyzer.py
Content-Security-Policy deep analysis + clickjacking detection (authorized, read-only).

Inspects the CSP header (and meta CSP) directive by directive and finds
weaknesses that open the door to XSS; also reports clickjacking risk
(embedding the page in an iframe) from missing X-Frame-Options / frame-ancestors.
Backs off on rate limits (429). In-scope targets only.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.csp")


@dataclass
class CSPFinding:
    directive: str
    severity: str
    detail: str


@dataclass
class CSPReport:
    target: str
    csp: str = ""
    inconclusive: bool = False
    findings: list = field(default_factory=list)


def _parse(csp: str) -> dict:
    out = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        out[toks[0].lower()] = [t.lower() for t in toks[1:]]
    return out


class CSPAnalyzer:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> CSPReport:
        rep = CSPReport(target=self.target)
        r = request(self.target, read_bytes=300_000)
        if r.status in (429, 403, 503) or r.status == 0:
            rep.inconclusive = True
            return rep

        csp = r.headers.get("content-security-policy", "")
        if not csp:
            m = re.search(r'http-equiv=["\']content-security-policy["\'][^>]+content=["\']([^"\']+)',
                          r.body or "", re.I)
            csp = m.group(1) if m else ""
        rep.csp = csp

        xfo = r.headers.get("x-frame-options", "")
        directives = _parse(csp)

        # --- Clickjacking ---
        if not xfo and "frame-ancestors" not in directives:
            rep.findings.append(CSPFinding("frame-ancestors/XFO", "MEDIUM",
                "Neither X-Frame-Options nor CSP frame-ancestors present — clickjacking possible."))

        if not csp:
            rep.findings.append(CSPFinding("(none)", "HIGH",
                "No CSP header — browser-side XSS defence is off."))
            log.info("CSP analysis (%s): no CSP.", self.target)
            return rep

        script = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script:
            rep.findings.append(CSPFinding("script-src", "HIGH",
                "script-src 'unsafe-inline' — inline scripts allowed, largely neutralizes XSS protection."))
        if "'unsafe-eval'" in script:
            rep.findings.append(CSPFinding("script-src", "MEDIUM",
                "script-src 'unsafe-eval' — eval() enabled, injection surface."))
        if "*" in script:
            rep.findings.append(CSPFinding("script-src", "HIGH",
                "script-src '*' — scripts can load from any source."))
        if any(s.startswith("http:") for s in script):
            rep.findings.append(CSPFinding("script-src", "MEDIUM",
                "script-src includes an http: source — mixed content / MITM risk."))
        if "object-src" not in directives:
            rep.findings.append(CSPFinding("object-src", "LOW",
                "object-src 'none' not set — legacy plugin-based XSS surface."))
        if "base-uri" not in directives:
            rep.findings.append(CSPFinding("base-uri", "LOW",
                "base-uri not set — base-URL hijacking risk via <base> injection."))

        if not rep.findings:
            rep.findings.append(CSPFinding("ok", "INFO", "CSP looks reasonable."))
        log.info("CSP analysis (%s): %d findings.", self.target, len(rep.findings))
        return rep
