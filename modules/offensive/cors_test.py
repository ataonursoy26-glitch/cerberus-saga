"""
modules/offensive/cors_test.py
CORS misconfiguration test (authorized, non-destructive).

Sends a request with a fake Origin header and inspects the Access-Control-Allow-Origin
(ACAO) response. Dangerous configurations:
  * ACAO reflects our arbitrary Origin verbatim + credentials are enabled
    -> an attacker site CAN READ API data using the user's session.
  * ACAO '*' + credentials 'true' -> dangerous, out-of-spec combination.
Read-only; only on targets listed in scope.yaml.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.cors")

EVIL_ORIGIN = "https://cerberus-evil.example"


@dataclass
class CORSFinding:
    severity: str
    detail: str


@dataclass
class CORSReport:
    target: str
    acao: str = ""
    acac: str = ""
    findings: list = field(default_factory=list)


class CORSTester:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> CORSReport:
        r = request(self.target, extra_headers={"Origin": EVIL_ORIGIN})
        rep = CORSReport(target=self.target)
        if r.status == 0:
            rep.findings.append(CORSFinding("INFO", f"Unreachable: {r.error}"))
            return rep
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        rep.acao, rep.acac = acao, acac

        if acao == EVIL_ORIGIN:
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            rep.findings.append(CORSFinding(sev,
                "ACAO reflects the arbitrary Origin we sent"
                + (" + credentials enabled → authenticated data theft possible." if acac.lower() == "true"
                   else " → resource sharing is overly permissive.")))
        elif acao == "*" and acac.lower() == "true":
            rep.findings.append(CORSFinding("HIGH",
                "ACAO '*' + credentials 'true' — dangerous/out-of-spec combination."))
        elif acao == "*":
            rep.findings.append(CORSFinding("LOW",
                "ACAO '*' — open to everyone (acceptable for a public API)."))
        else:
            rep.findings.append(CORSFinding("INFO",
                f"CORS looks safe (ACAO='{acao or 'none'}')."))
        log.info("CORS testi (%s): ACAO=%s", self.target, acao)
        return rep
