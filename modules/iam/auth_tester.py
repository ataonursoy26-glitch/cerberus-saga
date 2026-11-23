"""
modules/iam/auth_tester.py
Authentication: authentication resilience test
(Blueprint Volume 9, Module 9, Protocol 13).

Does NOT brute-force real accounts. Analyzes STRUCTURAL weaknesses such as
session token entropy, MFA enforcement and password-reset flow leaks, using
test inputs supplied by the client.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

from modules.iam._http import SafeHTTPClient

log = logging.getLogger("cerberus.iam.auth")


@dataclass
class AuthFinding:
    check: str
    severity: str
    detail: str


@dataclass
class AuthReport:
    target: str
    findings: List[AuthFinding] = field(default_factory=list)


class AuthenticationTester:
    def __init__(self, http_client=None) -> None:
        self.http = http_client or SafeHTTPClient()

    async def check_session_token_entropy(self, token: str) -> AuthFinding:
        if len(token) < 16 or len(set(token)) < 8:
            return AuthFinding("session_token_entropy", "HIGH",
                               "Session token is short/predictable; brute-force risk.")
        return AuthFinding("session_token_entropy", "INFO",
                           "Token length/variety looks reasonable.")

    async def check_mfa_enforcement(self, endpoint: str, session_cookie: str) -> AuthFinding:
        resp = await self.http.get(endpoint, cookies={"session": session_cookie})
        if resp.status_code == 200 and "mfa_pending" not in resp.text.lower():
            return AuthFinding("mfa_bypass_via_direct_session", "CRITICAL",
                               "A protected resource is reachable with a session obtained before MFA completed.")
        return AuthFinding("mfa_bypass_via_direct_session", "INFO",
                           "MFA is enforced before protected resources (or the target is down).")

    async def check_password_reset_flow(self, reset_response_text: str) -> AuthFinding:
        import re
        if re.search(r"user (not found|does not exist)|no account", reset_response_text, re.I):
            return AuthFinding("password_reset_user_enumeration", "MEDIUM",
                               "Password-reset flow leaks account existence via its message.")
        return AuthFinding("password_reset_user_enumeration", "INFO",
                           "Reset flow returns a generic/neutral message.")

    async def run_all(self, session_cookie: str, protected_endpoint: str,
                      reset_response_text: str) -> AuthReport:
        report = AuthReport(target=protected_endpoint)
        report.findings.append(await self.check_session_token_entropy(session_cookie))
        report.findings.append(await self.check_mfa_enforcement(protected_endpoint, session_cookie))
        report.findings.append(await self.check_password_reset_flow(reset_response_text))
        log.info("Authentication test: %d checks.", len(report.findings))
        return report
