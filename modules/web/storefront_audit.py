"""
modules/web/storefront_audit.py
E-commerce / Shopify storefront security & trust auditor.

Runs the NON-DESTRUCTIVE checks that matter most on a real store:
  * HTTPS enforcement (http -> https redirect)
  * Security headers: HSTS, CSP, X-Frame-Options (clickjacking),
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  * Cookie flags: Secure / HttpOnly / SameSite
  * Mixed content (http:// resource on an https page)
  * Presence of legal/trust pages (privacy, returns, terms, contact)
  * security.txt (/.well-known/security.txt)

Runs only on in-scope targets. Read-only; never modifies anything.
"""
from __future__ import annotations

import http.client
import logging
import re
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.storefront")

SECURITY_HEADERS = [
    ("strict-transport-security", "HIGH", "No HSTS: the browser does not enforce HTTPS, SSL-stripping risk."),
    ("content-security-policy", "MEDIUM", "No CSP: weak browser defense against XSS/data injection."),
    ("x-frame-options", "MEDIUM", "No X-Frame-Options: clickjacking (embedding your page in an iframe) risk."),
    ("x-content-type-options", "LOW", "No nosniff: MIME-type confusion risk."),
    ("referrer-policy", "LOW", "No Referrer-Policy: navigation data may leak to third parties."),
    ("permissions-policy", "LOW", "No Permissions-Policy: permissions like camera/location are unrestricted."),
]

# Standard Shopify legal/trust paths (checked at root and per-locale).
TRUST_PATHS = {
    "Privacy Policy": ["/policies/privacy-policy", "/en-uk/policies/privacy-policy"],
    "Refund Policy": ["/policies/refund-policy", "/en-uk/policies/refund-policy"],
    "Terms of Service": ["/policies/terms-of-service", "/en-uk/policies/terms-of-service"],
    "Shipping Policy": ["/policies/shipping-policy", "/en-uk/policies/shipping-policy"],
    "Contact Page": ["/pages/contact", "/en-uk/pages/contact"],
}


@dataclass
class Finding:
    area: str
    severity: str
    detail: str


@dataclass
class StorefrontReport:
    target: str
    findings: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    trust_pages: dict = field(default_factory=dict)
    inconclusive: bool = False


class StorefrontAuditor:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        parts = urlsplit(target if "://" in target else "https://" + target)
        self.host = parts.hostname
        self.base_path = parts.path.rstrip("/") or ""

    def _https(self, method: str, path: str, timeout: int = 8):
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.host, 443, timeout=timeout, context=ctx)
        conn.request(method, path or "/", headers={"User-Agent":
                     "Cerberus-Security-Scanner/1.0 (+authorized-pentest)"})
        resp = conn.getresponse()
        body = resp.read(300_000).decode("utf-8", "ignore") if method == "GET" else ""
        headers = {k.lower(): v for k, v in resp.getheaders()}
        cookies = resp.msg.get_all("Set-Cookie") or []
        status = resp.status
        conn.close()
        return status, headers, cookies, body

    def _http_redirect(self, timeout: int = 6):
        try:
            conn = http.client.HTTPConnection(self.host, 80, timeout=timeout)
            conn.request("HEAD", "/", headers={"User-Agent": "Cerberus/1.0"})
            resp = conn.getresponse()
            loc = resp.getheader("Location", "")
            conn.close()
            return resp.status, loc
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc)[:60]

    def audit(self) -> StorefrontReport:
        report = StorefrontReport(target=self.host)
        try:
            status, headers, cookies, body = self._https("GET", self.base_path or "/")
        except Exception as exc:  # noqa: BLE001
            report.findings.append(Finding("Connection", "INFO", f"HTTPS request failed: {exc}"))
            return report
        # Rate-limited / unreachable: we could not fetch the real page -> do NOT emit a fake finding.
        if status in (429, 403, 503) or status == 0:
            report.findings.append(Finding("Access", "INFO",
                f"Target could not be audited (HTTP {status} — likely rate-limit/WAF). "
                "Result inconclusive; try again later."))
            report.inconclusive = True
            return report
        report.headers = headers
        report.cookies = cookies

        # 1) Security headers
        for name, sev, msg in SECURITY_HEADERS:
            present = name in headers or (name == "x-frame-options"
                                          and "frame-ancestors" in headers.get("content-security-policy", ""))
            if not present:
                report.findings.append(Finding("Security Header", sev, msg))

        # 2) HTTPS enforcement
        hstatus, loc = self._http_redirect()
        if hstatus in (301, 302, 307, 308) and loc.startswith("https"):
            pass  # iyi
        elif hstatus == 0:
            report.findings.append(Finding("HTTPS", "INFO", "HTTP (80) check could not be performed."))
        else:
            report.findings.append(Finding("HTTPS", "HIGH",
                f"HTTP (80) does not redirect to secure HTTPS (status {hstatus})."))

        # 3) Cookie flags
        for c in cookies:
            cl = c.lower()
            name = c.split("=", 1)[0]
            missing = [flag for flag, key in
                       (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                       if key not in cl]
            if missing:
                report.findings.append(Finding("Cookie", "LOW",
                    f"Cookie '{name}' is missing flag(s): {', '.join(missing)}."))

        # 4) Mixed content
        mixed = re.findall(r'(?:src|href)=["\']http://[^"\']+', body)
        if mixed:
            report.findings.append(Finding("Mixed Content", "MEDIUM",
                f"The HTTPS page references {len(mixed)} http:// resource(s)."))

        # 5) security.txt
        try:
            st, _, _, _ = self._https("GET", "/.well-known/security.txt")
            if st != 200:
                report.findings.append(Finding("security.txt", "LOW",
                    "/.well-known/security.txt missing: how would a security researcher reach you?"))
        except Exception:  # noqa: BLE001
            pass

        # 6) Legal/trust pages
        for label, paths in TRUST_PATHS.items():
            found = False
            for p in paths:
                try:
                    s, _, _, _ = self._https("GET", p)
                    if s == 200:
                        found = True
                        break
                except Exception:  # noqa: BLE001
                    continue
            report.trust_pages[label] = found
            if not found:
                report.findings.append(Finding("Trust Page", "MEDIUM",
                    f"{label} not found (needed for customer trust + legal compliance)."))

        log.info("Storefront audit: %d findings.", len(report.findings))
        return report
