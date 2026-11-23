"""
modules/offensive/js_secret_scan.py
Client-side (JS/HTML) secret leak scanner (authorized, read-only).

Fetches the target's home page and its linked JavaScript files and searches
them for embedded API keys / tokens / exchange keys / wallet secrets.
Secrets accidentally shipped to the frontend (Stripe secret key, AWS key, etc.)
are a very common, real leak class. Findings are masked.
Backs off on rate limits (429). In-scope targets only.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request
from modules.dlp.pii_spii_scanner import PIISPIIScanner
from modules.crypto.exchange_guard import ExchangeGuard

log = logging.getLogger("cerberus.jsleak")

SECRET_CATS = {
    "AWS_ACCESS_KEY", "STRIPE_SECRET_KEY", "GITHUB_PAT", "GITHUB_OAUTH_TOKEN",
    "GCP_API_KEY", "SLACK_TOKEN", "SENDGRID_API_KEY", "TWILIO_API_KEY",
    "PRIVATE_KEY_BLOCK", "GENERIC_PRIVATE_KEY_BLOCK", "DATABASE_CONNECTION_STRING",
    "GENERIC_API_KEY", "NPM_ACCESS_TOKEN", "DOCKER_HUB_TOKEN",
}


@dataclass
class JSLeakFinding:
    source: str
    category: str
    severity: str
    masked: str


@dataclass
class JSLeakReport:
    target: str
    scripts_scanned: int = 0
    inconclusive: bool = False
    findings: list = field(default_factory=list)


class JSSecretScanner:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target
        self.dlp = PIISPIIScanner()
        self.crypto = ExchangeGuard()

    def _scan_blob(self, source: str, text: str, rep: JSLeakReport) -> None:
        for f in self.dlp.scan_text(text, source).findings:
            if f.category in SECRET_CATS and f.severity in ("HIGH", "CRITICAL"):
                rep.findings.append(JSLeakFinding(source, f.category, f.severity, f.match_masked))
        for f in self.crypto.scan_text(text).findings:
            if f.kind in ("EXCHANGE_API_KEY", "WALLET_PRIVATE_KEY", "SEED_PHRASE"):
                rep.findings.append(JSLeakFinding(source, f.kind, f.severity, f.masked))

    def run(self, max_scripts: int = 12) -> JSLeakReport:
        rep = JSLeakReport(target=self.target)
        root = request(self.target, read_bytes=1_000_000)
        if root.status in (429, 403, 503) or root.status == 0:
            rep.inconclusive = True
            return rep
        body = root.body or ""
        self._scan_blob("(ana sayfa)", body, rep)

        # Collect linked <script src=...> files
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
        seen = set()
        for src in srcs:
            if len(seen) >= max_scripts:
                break
            url = urljoin(self.target, src)
            if urlsplit(url).scheme not in ("http", "https") or url in seen:
                continue
            seen.add(url)
            r = request(url, read_bytes=2_000_000)
            if r.status == 200 and r.body:
                rep.scripts_scanned += 1
                self._scan_blob(src.split("/")[-1][:40], r.body, rep)
        log.info("JS secret scan (%s): %d scripts, %d findings.",
                 self.target, rep.scripts_scanned, len(rep.findings))
        return rep
