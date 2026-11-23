"""
modules/dlp/financial_scanner.py
Financial data classifier (Blueprint Volume 11, Module 11).

IBAN (mod-97), SWIFT/BIC, US ABA routing (checksum), EIN/VAT, BTC/ETH
wallet addresses and contextual bank account number detection. For PCI-DSS
scope pre-flagging. Fully local; findings are masked.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class FinancialFinding:
    category: str
    severity: str
    match_masked: str
    context_snippet: str
    location: str


@dataclass
class FinancialReport:
    target: str
    findings: List[FinancialFinding] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out


FINANCIAL_PATTERNS = {
    "IBAN_INTL": (r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", "CRITICAL"),
    "SWIFT_BIC": (r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", "HIGH"),
    "US_ABA_ROUTING": (r"\b\d{9}\b", "CRITICAL"),
    "EIN_US": (r"\b\d{2}-\d{7}\b", "MEDIUM"),
    "VAT_EU": (r"\b[A-Z]{2}\d{8,12}\b", "MEDIUM"),
    "CRYPTO_BTC_ADDRESS": (r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", "MEDIUM"),
    "CRYPTO_ETH_ADDRESS": (r"\b0x[a-fA-F0-9]{40}\b", "MEDIUM"),
}

CONTEXTUAL_FINANCIAL_PATTERNS = {
    "BANK_ACCOUNT_CONTEXTUAL": {
        "trigger_words": ["account number", "hesap no", "iban", "acct #", "hesap numarası"],
        "pattern": r"\b\d{8,17}\b", "severity": "HIGH", "window": 35},
}


def _iban_mod97_valid(iban: str) -> bool:
    iban = iban.replace(" ", "").upper()
    if len(iban) < 15:
        return False
    rearranged = iban[4:] + iban[:4]
    try:
        converted = "".join(str(int(c, 36)) for c in rearranged)
        return int(converted) % 97 == 1
    except ValueError:
        return False


def _aba_routing_valid(number: str) -> bool:
    if len(number) != 9 or not number.isdigit():
        return False
    d = [int(c) for c in number]
    checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + 1 * (d[2] + d[5] + d[8])
    return checksum % 10 == 0


VALIDATORS = {"IBAN_INTL": _iban_mod97_valid, "US_ABA_ROUTING": _aba_routing_valid}


def _mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


class FinancialDataScanner:
    def __init__(self) -> None:
        self.compiled = {k: (re.compile(v[0]), v[1]) for k, v in FINANCIAL_PATTERNS.items()}

    def scan_text(self, text: str, location: str = "unknown") -> FinancialReport:
        report = FinancialReport(target=location)
        for category, (pattern, severity) in self.compiled.items():
            for match in pattern.finditer(text):
                raw = match.group(0)
                validator = VALIDATORS.get(category)
                if validator and not validator(raw):
                    continue
                start, end = max(match.start() - 15, 0), min(match.end() + 15, len(text))
                ctx = text[start:end].replace(raw, _mask(raw))
                report.findings.append(FinancialFinding(
                    category=category, severity=severity,
                    match_masked=_mask(raw), context_snippet=ctx, location=location))

        lowered = text.lower()
        for category, cfg in CONTEXTUAL_FINANCIAL_PATTERNS.items():
            compiled = re.compile(cfg["pattern"])
            for trigger in cfg["trigger_words"]:
                idx = lowered.find(trigger.lower())
                while idx != -1:
                    w = cfg["window"]
                    seg_start = max(idx - w, 0)
                    seg_end = min(idx + len(trigger) + w, len(text))
                    segment = text[seg_start:seg_end]
                    for m in compiled.finditer(segment):
                        raw = m.group(0)
                        report.findings.append(FinancialFinding(
                            category=category, severity=cfg["severity"],
                            match_masked=_mask(raw),
                            context_snippet=segment.replace(raw, _mask(raw)),
                            location=location))
                    idx = lowered.find(trigger.lower(), idx + 1)
        return report

    async def scan_async(self, text: str, location: str = "unknown") -> FinancialReport:
        return self.scan_text(text, location)
