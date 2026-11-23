"""
modules/dlp/secret_audit.py
Local secret leak audit (gitleaks / truffleHog style).

Scans text files in a given directory line by line and finds SECRETS
accidentally embedded in code, such as API keys, tokens, private keys and
DB connection strings. Runs fully LOCALLY — only the user's own files,
nothing is sent out. Findings are masked.

Focuses only on HIGH/CRITICAL secret categories (filters out low-signal
PII such as email/phone) to keep noise low.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from modules.dlp.pii_spii_scanner import PIISPIIScanner

log = logging.getLogger("cerberus.secret")

SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", ".next",
             "dist", "build", ".cache", ".idea", "reports", "storage"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
            ".gz", ".mp4", ".mov", ".mp3", ".woff", ".woff2", ".ttf", ".lock",
            ".so", ".dylib", ".pyc", ".bin", ".svg"}
MAX_FILE_BYTES = 1_000_000

# Only real "secret" categories (not PII).
SECRET_CATEGORIES = {
    "AWS_ACCESS_KEY", "GENERIC_API_KEY", "PRIVATE_KEY_BLOCK", "GCP_API_KEY",
    "GCP_SERVICE_ACCOUNT_JSON", "AZURE_STORAGE_KEY", "AZURE_CONNECTION_STRING",
    "STRIPE_SECRET_KEY", "TWILIO_API_KEY", "SENDGRID_API_KEY", "MAILGUN_API_KEY",
    "GITHUB_PAT", "GITHUB_OAUTH_TOKEN", "SLACK_TOKEN", "SLACK_WEBHOOK_URL",
    "NPM_ACCESS_TOKEN", "DOCKER_HUB_TOKEN", "JWT_TOKEN",
    "DATABASE_CONNECTION_STRING", "GENERIC_PRIVATE_KEY_BLOCK", "CRYPTO_WALLET_KEY",
}


@dataclass
class SecretFinding:
    file: str
    line: int
    category: str
    severity: str
    match_masked: str


@dataclass
class SecretReport:
    root: str
    files_scanned: int = 0
    findings: list = field(default_factory=list)


class SecretAuditor:
    def __init__(self) -> None:
        self.scanner = PIISPIIScanner()

    def scan_dir(self, root: str, max_files: int = 5000) -> SecretReport:
        root_path = Path(root).expanduser().resolve()
        report = SecretReport(root=str(root_path))
        if not root_path.exists():
            log.warning("Directory not found: %s", root_path)
            return report

        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for name in filenames:
                if report.files_scanned >= max_files:
                    return report
                fp = Path(dirpath) / name
                if fp.suffix.lower() in SKIP_EXT:
                    continue
                try:
                    if fp.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                except Exception:  # noqa: BLE001
                    continue
                report.files_scanned += 1
                self._scan_file(fp, text, root_path, report)
        log.info("Secret audit: %d files, %d findings.", report.files_scanned, len(report.findings))
        return report

    def _scan_file(self, fp: Path, text: str, root: Path, report: SecretReport) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 4000:
                continue
            rep = self.scanner.scan_text(line, str(fp))
            for f in rep.findings:
                if f.category in SECRET_CATEGORIES and f.severity in ("HIGH", "CRITICAL"):
                    try:
                        rel = str(fp.relative_to(root))
                    except ValueError:
                        rel = str(fp)
                    report.findings.append(SecretFinding(
                        file=rel, line=i, category=f.category,
                        severity=f.severity, match_masked=f.match_masked))
