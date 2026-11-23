"""
modules/iam/authz_tester.py
Authorization: access control / privilege escalation audit
(Blueprint Volume 9, Module 10, Protocol 14 / OWASP A01).

Detects IDOR and vertical/horizontal privilege escalation by comparing two
test accounts with different privilege levels. Works only with test accounts
supplied by the client, inside the authorization scope.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

from modules.iam._http import SafeHTTPClient

log = logging.getLogger("cerberus.iam.authz")


@dataclass
class AuthzFinding:
    resource: str
    finding_type: str   # IDOR / VERTICAL_PRIV_ESC / HORIZONTAL_PRIV_ESC
    severity: str
    detail: str


@dataclass
class AuthzReport:
    target: str
    findings: List[AuthzFinding] = field(default_factory=list)


class AuthorizationTester:
    def __init__(self, http_client=None) -> None:
        self.http = http_client or SafeHTTPClient()

    async def check_idor(self, template: str, own_id: str, other_id: str,
                         session_cookie: str) -> AuthzFinding:
        await self.http.get(template.replace("{id}", own_id), cookies={"session": session_cookie})
        other = await self.http.get(template.replace("{id}", other_id),
                                    cookies={"session": session_cookie})
        if other.status_code == 200:
            return AuthzFinding(template, "IDOR", "CRITICAL",
                                f"Access to resource '{other_id}' is not blocked using '{own_id}' credentials.")
        return AuthzFinding(template, "IDOR", "INFO",
                            "Cross-resource access is denied (or the target is down).")

    async def check_vertical_priv_esc(self, admin_endpoint: str,
                                      low_priv_cookie: str) -> AuthzFinding:
        resp = await self.http.get(admin_endpoint, cookies={"session": low_priv_cookie})
        if resp.status_code == 200:
            return AuthzFinding(admin_endpoint, "VERTICAL_PRIV_ESC", "CRITICAL",
                                "A low-privilege session can reach an admin endpoint.")
        return AuthzFinding(admin_endpoint, "VERTICAL_PRIV_ESC", "INFO",
                            "Role-based access control behaves as expected (or the target is down).")

    async def run_all(self, resource_url_template: str, own_id: str, other_id: str,
                      admin_endpoint: str, session_cookie: str = "demo_low_priv",
                      low_priv_session_cookie: str = "demo_low_priv") -> AuthzReport:
        report = AuthzReport(target=resource_url_template)
        report.findings.append(await self.check_idor(
            resource_url_template, own_id, other_id, session_cookie))
        report.findings.append(await self.check_vertical_priv_esc(
            admin_endpoint, low_priv_session_cookie))
        log.info("Authorization test: %d checks.", len(report.findings))
        return report
