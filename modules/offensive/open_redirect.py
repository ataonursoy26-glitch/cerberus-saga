"""
modules/offensive/open_redirect.py
Open redirect test (authorized, non-destructive).

Puts an external address into common redirect parameters and checks whether
the server redirects to it (Location header).
If it does, an attacker can send users through the trusted domain
to their own phishing site. Does NOT follow the redirect;
only reads the Location header.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.redirect")

REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_url", "return", "return_url",
                   "returnTo", "dest", "destination", "continue", "r", "u", "goto"]
EVIL = "https://cerberus-evil.example/pwn"


@dataclass
class RedirectFinding:
    param: str
    severity: str
    detail: str


@dataclass
class RedirectReport:
    target: str
    findings: list = field(default_factory=list)


def _off_site(location: str) -> bool:
    loc = location.strip().lower()
    return ("cerberus-evil.example" in loc) and (
        loc.startswith("http://") or loc.startswith("https://") or loc.startswith("//"))


class OpenRedirectTester:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.base = target if "://" in target else "https://" + target
        self.base = self.base.split("?")[0]

    def run(self) -> RedirectReport:
        rep = RedirectReport(target=self.base)
        for p in REDIRECT_PARAMS:
            url = f"{self.base}?{p}={EVIL}"
            r = request(url)
            if r.status in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                if _off_site(loc):
                    rep.findings.append(RedirectFinding(p, "MEDIUM",
                        f"Parameter '{p}' redirects to an external address (Location: {loc[:60]})."))
        if not rep.findings:
            rep.findings.append(RedirectFinding("-", "INFO",
                "No open redirect found in common parameters."))
        log.info("Open-redirect test (%s): %d findings.", self.base, len(rep.findings))
        return rep
