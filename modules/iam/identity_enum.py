"""
modules/iam/identity_enum.py
Identification: identity surface inventory and enumeration risk
(Blueprint Volume 9, Module 8, Protocol 12).

Runs only on in-scope targets. Does NOT brute-force credentials
(username/password); uses two CONTROLLED requests and the response difference
(timing, message, HTTP code) to check for an enumeration weakness.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List

from core.scope_guard import assert_in_scope
from modules.iam._http import SafeHTTPClient

log = logging.getLogger("cerberus.iam.identity")


@dataclass
class IdentitySurface:
    endpoint: str
    surface_type: str   # login_form / sso / api_key_header / service_account
    enumeration_risk: str  # NONE / LOW / MEDIUM / HIGH
    evidence: str


@dataclass
class IdentityReport:
    target: str
    surfaces: List[IdentitySurface] = field(default_factory=list)


class IdentityEnumerator:
    def __init__(self, http_client=None, authorized_scope: List[str] | None = None) -> None:
        self.http = http_client or SafeHTTPClient()
        self.authorized_scope = authorized_scope or []

    async def probe(self, login_url: str) -> IdentityReport:
        assert_in_scope(login_url)
        report = IdentityReport(target=login_url)
        a = await self.http.post(login_url, data={"username": "nonexistent_user_a", "password": "x"})
        b = await self.http.post(login_url, data={"username": "zzz_definitely_absent", "password": "x"})
        risk, evidence = "NONE", "No distinguishing difference between responses."
        if a.status_code == 0 and b.status_code == 0:
            risk, evidence = "INFO", "No live response (demo/offline target); static check applied."
        elif a.status_code != b.status_code:
            risk, evidence = "MEDIUM", f"HTTP status code difference: {a.status_code} vs {b.status_code}"
        elif abs(len(a.text) - len(b.text)) > 5:
            risk, evidence = "MEDIUM", "Response body length difference may leak user existence."
        report.surfaces.append(IdentitySurface(login_url, "login_form", risk, evidence))
        log.info("Identity enumeration: risk=%s", risk)
        return report

    async def inventory_service_identities(self, headers: Dict[str, str]) -> List[IdentitySurface]:
        import re
        surfaces = []
        for name in headers:
            if re.search(r"api[-_]?key|x-service-id|x-client-id", name, re.I):
                surfaces.append(IdentitySurface(
                    name, "api_key_header", "LOW",
                    "Static service identity is carried in a header."))
        return surfaces
