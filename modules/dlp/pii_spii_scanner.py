"""
modules/dlp/pii_spii_scanner.py
PII/SPII + extended secret detection engine (Blueprint Volume 3/10, Module 7 + 7-B).

Runs fully LOCAL/OFFLINE. No external API dependency; sensitive data is
never sent out. Findings are always MASKED (match_masked); raw match text
is never written to a persistent log (Blueprint Volume 7 data minimization + Volume 8).

Techniques:
  1. Deterministic regex + checksum (Luhn / Turkish national ID / mod-based) validation
  2. Shannon entropy (catches unstructured passwords/secrets, threshold > 3.5)
  3. Context window + suppression (context_filter) to reduce false positives
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List

from modules.dlp.context_filter import find_contextual_matches, is_suppressed_context


@dataclass
class PIIFinding:
    category: str
    severity: str
    match_masked: str
    context_snippet: str
    location: str
    count: int = 1


@dataclass
class ScanReport:
    target: str
    findings: List[PIIFinding] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + f.count
        return out


# --- Core signatures (Volume 3, Module 7) ----------------------------------------
PATTERNS = {
    "EMAIL": (r"[a-zA-Z0-9.%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "LOW"),
    "PHONE_TR": (r"(?<!\d)(?:\+90|0)?5\d{2}[\s.\-]?\d{3}[\s.\-]?\d{2}[\s.\-]?\d{2}(?!\d)", "MEDIUM"),
    "IBAN": (r"\bTR\d{2}\s?(?:\d{4}\s?){5}\d{2}\b", "HIGH"),
    "TC_KIMLIK_NO": (r"\b[1-9]\d{10}\b", "CRITICAL"),
    "CREDIT_CARD": (r"\b(?:\d[ \-]?){13,16}\b", "CRITICAL"),
    "US_SSN": (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL"),
    "AWS_ACCESS_KEY": (r"\bAKIA[0-9A-Z]{16}\b", "CRITICAL"),
    "GENERIC_API_KEY": (r"(?:api[_-]?key|secret|token)[\"'\s:=]{1,4}[A-Za-z0-9_\-]{20,}", "HIGH"),
    "PRIVATE_KEY_BLOCK": (r"-----BEGIN (?:RSA|EC|OPENSSH)? ?PRIVATE KEY-----", "CRITICAL"),
}

# --- Extended signatures (Volume 10, Module 7-B) -----------------------------
EXTENDED_PATTERNS = {
    "GCP_API_KEY": (r"AIza[0-9A-Za-z_\-]{35}", "CRITICAL"),
    "GCP_SERVICE_ACCOUNT_JSON": (r'"type"\s*:\s*"service_account"', "CRITICAL"),
    "AZURE_STORAGE_KEY": (r"[A-Za-z0-9+/]{86}==", "CRITICAL"),
    "AZURE_CONNECTION_STRING": (r"AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}", "CRITICAL"),
    "STRIPE_SECRET_KEY": (r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "STRIPE_PUBLISHABLE_KEY": (r"pk_live_[0-9a-zA-Z]{24,}", "LOW"),
    "TWILIO_API_KEY": (r"\bSK[0-9a-fA-F]{32}\b", "HIGH"),
    "SENDGRID_API_KEY": (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "HIGH"),
    "MAILGUN_API_KEY": (r"\bkey-[0-9a-f]{32}\b", "HIGH"),
    "GITHUB_PAT": (r"(?:ghp|github_pat)_[A-Za-z0-9_]{36,}", "CRITICAL"),
    "GITHUB_OAUTH_TOKEN": (r"gh[ous]_[A-Za-z0-9]{36,}", "HIGH"),
    "SLACK_TOKEN": (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "HIGH"),
    "SLACK_WEBHOOK_URL": (r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", "MEDIUM"),
    "NPM_ACCESS_TOKEN": (r"npm_[A-Za-z0-9]{36}", "HIGH"),
    "DOCKER_HUB_TOKEN": (r"dckr_pat_[A-Za-z0-9_\-]{20,}", "HIGH"),
    "JWT_TOKEN": (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "MEDIUM"),
    "DATABASE_CONNECTION_STRING": (
        r"(?:postgres|mysql|mongodb(?:\+srv)?)://[^:\s]+:[^@\s]+@[^\s/]+", "CRITICAL"),
    "GENERIC_PRIVATE_KEY_BLOCK": (
        r"-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA)? ?PRIVATE KEY-----", "CRITICAL"),
    "CRYPTO_WALLET_KEY": (r"\b[0-9a-fA-F]{64}\b", "CRITICAL"),  # entropi filtreli
}

# --- Context-dependent (unstructured) fields (Volume 10) -----------------------------
CONTEXTUAL_PATTERNS = {
    "PASSPORT_NUMBER_GENERIC": {
        "trigger_words": ["passport", "pasaport", "passport no", "passport number"],
        "pattern": r"\b[A-Z0-9]{6,9}\b", "severity": "HIGH", "window": 40},
    "US_DRIVER_LICENSE": {
        "trigger_words": ["driver's license", "driver license", "ehliyet no", "dl number"],
        "pattern": r"\b[A-Z0-9]{6,12}\b", "severity": "MEDIUM", "window": 40},
    "HEALTH_INSURANCE_NO": {
        "trigger_words": ["sigorta no", "policy number", "insurance id", "member id"],
        "pattern": r"\b[A-Z0-9\-]{8,15}\b", "severity": "HIGH", "window": 40},
}


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _tc_kimlik_valid(no: str) -> bool:
    if len(no) != 11 or not no.isdigit() or no[0] == "0":
        return False
    d = [int(c) for c in no]
    d10 = ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10
    d11 = sum(d[0:10]) % 10
    return d[9] == d10 and d[10] == d11


VALIDATORS = {"CREDIT_CARD": _luhn_valid, "TC_KIMLIK_NO": _tc_kimlik_valid}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq = {c: s.count(c) for c in set(s)}
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


class PIISPIIScanner:
    def __init__(self, min_entropy_for_secrets: float = 3.5) -> None:
        self.min_entropy = min_entropy_for_secrets
        merged = {**PATTERNS, **EXTENDED_PATTERNS}
        self.compiled = {k: (re.compile(v[0]), v[1]) for k, v in merged.items()}

    def scan_text(self, text: str, location: str = "unknown") -> ScanReport:
        report = ScanReport(target=location)

        # 1. Deterministic + entropy pass
        for category, (pattern, severity) in self.compiled.items():
            for match in pattern.finditer(text):
                raw = match.group(0)
                validator = VALIDATORS.get(category)
                if validator and not validator(re.sub(r"\D", "", raw)):
                    continue
                if category in ("GENERIC_API_KEY", "CRYPTO_WALLET_KEY"):
                    candidate = raw.split("=")[-1].strip("\"' ")
                    if _shannon_entropy(candidate) < self.min_entropy:
                        continue
                # CRYPTO_WALLET_KEY: 64-hex strings collide with asset/ETag hashes.
                # To avoid false positives, require a nearby "wallet/key" anchor.
                if category == "CRYPTO_WALLET_KEY":
                    ctx_lo = text[max(match.start() - 40, 0):min(match.end() + 40, len(text))].lower()
                    if not any(a in ctx_lo for a in
                               ("wallet", "priv", "private key", "seed", "mnemonic", "0x", "cüzdan", "anahtar")):
                        continue
                eff_sev = "INFO" if is_suppressed_context(text, match.start(), match.end()) else severity
                start, end = max(match.start() - 15, 0), min(match.end() + 15, len(text))
                context = text[start:end].replace(raw, _mask(raw))
                report.findings.append(PIIFinding(
                    category=category, severity=eff_sev,
                    match_masked=_mask(raw), context_snippet=context, location=location))

        # 2. Context-dependent pass
        for category, cfg in CONTEXTUAL_PATTERNS.items():
            for s, e, raw in find_contextual_matches(
                    text, cfg["trigger_words"], cfg["pattern"], cfg["window"]):
                eff_sev = "INFO" if is_suppressed_context(text, s, e) else cfg["severity"]
                ctx = text[max(s - 15, 0):min(e + 15, len(text))].replace(raw, _mask(raw))
                report.findings.append(PIIFinding(
                    category=category, severity=eff_sev,
                    match_masked=_mask(raw), context_snippet=ctx, location=location))
        return report

    async def scan_async(self, text: str, location: str = "unknown") -> ScanReport:
        return self.scan_text(text, location)
