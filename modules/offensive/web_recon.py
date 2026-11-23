"""
modules/offensive/web_recon.py
Active web recon — sensitive path/file exposure (authorized pentest).

Checks whether known sensitive paths are accessible on a target
(GET-only, non-destructive). A hit signals data leakage/misconfiguration:
.git, .env, backup files, exposed .json endpoints, directory listing, server status.
Runs only on targets within the scope.yaml scope.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.recon")

# (path, severity, description)
SENSITIVE_PATHS = [
    ("/.git/config", "CRITICAL", "Exposed .git repository — the entire source code can be downloaded."),
    ("/.git/HEAD", "CRITICAL", "Exposed .git repository (HEAD)."),
    ("/.env", "CRITICAL", ".env file exposed — secrets/keys may leak."),
    ("/.env.local", "CRITICAL", ".env.local exposed."),
    ("/config.php", "HIGH", "Configuration file is accessible."),
    ("/wp-config.php", "CRITICAL", "WordPress configuration is accessible."),
    ("/backup.zip", "HIGH", "Backup archive exposed."),
    ("/backup.sql", "CRITICAL", "Database dump exposed."),
    ("/db.sql", "CRITICAL", "Database dump exposed."),
    ("/.DS_Store", "LOW", ".DS_Store — directory structure leakage."),
    ("/.htaccess", "MEDIUM", ".htaccess is accessible."),
    ("/server-status", "MEDIUM", "Apache server-status is exposed."),
    ("/phpinfo.php", "MEDIUM", "phpinfo() exposed — environment info leakage."),
    ("/.well-known/security.txt", "INFO", "security.txt mevcut (iyi uygulama)."),
    ("/robots.txt", "INFO", "robots.txt mevcut."),
    # Shopify / e-commerce specific endpoints
    ("/products.json", "MEDIUM", "Shopify products.json exposed — the product catalog can be bulk-pulled."),
    ("/cart.json", "LOW", "cart.json is accessible."),
    ("/collections.json", "LOW", "collections.json is exposed."),
]


@dataclass
class ReconFinding:
    path: str
    status: int
    severity: str
    detail: str


@dataclass
class ReconReport:
    target: str
    tested: int = 0
    findings: list = field(default_factory=list)
    methods_allowed: str = ""


class WebRecon:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.base = target.rstrip("/")
        if "://" not in self.base:
            self.base = "http://" + self.base

    @staticmethod
    def _is_html(body: str) -> bool:
        head = body[:400].lower()
        return "<!doctype html" in head or "<html" in head or "<title" in head

    @staticmethod
    def _looks_json(body: str) -> bool:
        s = body.lstrip()
        return s.startswith("{") or s.startswith("[")

    def _soft404(self, baseline, body: str) -> bool:
        """Is the response the same as the 'soft 404' page returned for a nonexistent path?"""
        if baseline.status != 200 or not baseline.body:
            return False
        # if the length is very close it is the same template page
        if abs(len(body) - len(baseline.body)) < max(50, len(baseline.body) * 0.1):
            return True
        return False

    def run(self) -> ReconReport:
        rep = ReconReport(target=self.base)

        # Baseline: a random nonexistent path -> the site's 'soft 404' behavior
        import uuid
        baseline = request(self.base + "/cerberus-404-" + uuid.uuid4().hex[:8], timeout=5)

        for path, sev, desc in SENSITIVE_PATHS:
            r = request(self.base + path, timeout=5)
            rep.tested += 1
            if r.status != 200 or not r.body:
                continue
            if self._soft404(baseline, r.body):
                continue  # not a real file, just the template 404 page

            is_json_path = path.endswith(".json")
            if is_json_path:
                if not self._looks_json(r.body):
                    continue  # not a JSON endpoint, returned HTML -> ignore
            else:
                # file/hidden path: if it returns an HTML page it is not a real exposure
                if self._is_html(r.body):
                    continue

            rep.findings.append(ReconFinding(path, r.status, sev, desc))
            if "Index of /" in r.body:
                rep.findings.append(ReconFinding(path, 200, "MEDIUM",
                    "Directory listing is enabled (Index of /)."))

        # HTTP methods
        opt = request(self.base + "/", method="OPTIONS")
        allow = opt.headers.get("allow", "")
        rep.methods_allowed = allow
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
        if risky:
            rep.findings.append(ReconFinding("/", opt.status, "MEDIUM",
                f"Risky HTTP methods enabled: {', '.join(risky)}"))

        log.info("Web recon (%s): %d paths tested, %d findings.",
                 self.base, rep.tested, len(rep.findings))
        return rep
