"""
modules/offensive/host_header.py
Host header injection detection (authorized, non-destructive).

Sends a request with a fake Host / X-Forwarded-Host header and checks whether
that value is REFLECTED in the response body or the Location redirect.
If reflected: password-reset poisoning (the attacker's domain lands in the link),
web-cache poisoning and SSRF-like risks may be possible.
In-scope targets only; read-only.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.hosthdr")

EVIL = "cerberus-evil.example"


@dataclass
class HostFinding:
    vector: str
    severity: str
    detail: str


@dataclass
class HostReport:
    target: str
    findings: list = field(default_factory=list)


class HostHeaderTester:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> HostReport:
        rep = HostReport(target=self.target)
        for vector, headers in (
            ("Host", {"Host": EVIL}),
            ("X-Forwarded-Host", {"X-Forwarded-Host": EVIL}),
            ("X-Host", {"X-Host": EVIL}),
        ):
            r = request(self.target, extra_headers=headers)
            loc = r.headers.get("location", "")
            if EVIL in loc:
                rep.findings.append(HostFinding(vector, "HIGH",
                    f"Fake {vector} value reflected in the Location redirect ({loc[:60]}) — "
                    "password-reset poisoning risk."))
            elif r.body and EVIL in r.body:
                rep.findings.append(HostFinding(vector, "MEDIUM",
                    f"Fake {vector} value reflected in the response body — cache poisoning / link poisoning risk."))
        if not rep.findings:
            rep.findings.append(HostFinding("-", "INFO",
                "Fake Host headers were not reflected (looks safe)."))
        log.info("Host header test (%s): %d findings.", self.target, len(rep.findings))
        return rep
