"""
modules/web/email_security.py
Email security / anti-spoofing audit (SPF, DMARC, DKIM, MX).

CHECKS from DNS TXT records whether a domain is protected against email
spoofing/phishing. Purely passive DNS queries; no packets are sent to the
target. Missing DMARC is very common on Shopify/e-commerce stores, and it means
forged email can be sent in the brand's name.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger("cerberus.email")


@dataclass
class EmailFinding:
    check: str
    severity: str
    detail: str


@dataclass
class EmailReport:
    domain: str
    records: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


def _dig_txt(name: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        out = subprocess.run(["dig", "+short", "TXT", name],
                             capture_output=True, text=True, timeout=8).stdout
        return [line.strip().strip('"') for line in out.splitlines() if line.strip()]
    except Exception:  # noqa: BLE001
        return []


def _dig(name: str, rtype: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        out = subprocess.run(["dig", "+short", rtype, name],
                             capture_output=True, text=True, timeout=8).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:  # noqa: BLE001
        return []


# Common DKIM selectors — whichever exists is found.
DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "s1", "dkim", "mail"]


class EmailSecurityAuditor:
    def audit(self, domain: str) -> EmailReport:
        domain = domain.split("://")[-1].split("/")[0].split(":")[0]
        # Email is sent from the root (registered) domain; strip 'www.' and similar subdomains.
        if domain.startswith("www."):
            domain = domain[4:]
        rep = EmailReport(domain=domain)

        # --- SPF ---
        txts = _dig_txt(domain)
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        rep.records["spf"] = spf or ""
        if not spf:
            rep.findings.append(EmailFinding("SPF", "HIGH",
                "No SPF record: others can pretend to send email from your domain."))
        elif "+all" in spf:
            rep.findings.append(EmailFinding("SPF", "HIGH",
                "SPF contains '+all': anyone may send — no protection."))
        elif "~all" not in spf and "-all" not in spf:
            rep.findings.append(EmailFinding("SPF", "MEDIUM",
                "SPF record has no '-all'/'~all' terminator: weak protection."))

        # --- DMARC ---
        dmarc_txts = _dig_txt("_dmarc." + domain)
        dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
        rep.records["dmarc"] = dmarc or ""
        if not dmarc:
            rep.findings.append(EmailFinding("DMARC", "HIGH",
                "No DMARC record: phishing/spoofing email in the brand's name cannot be blocked."))
        else:
            pol = re.search(r"p=(\w+)", dmarc)
            policy = pol.group(1) if pol else "none"
            if policy == "none":
                rep.findings.append(EmailFinding("DMARC", "MEDIUM",
                    "DMARC policy 'p=none': monitored but forged mail is NOT blocked. 'quarantine'/'reject' recommended."))

        # --- DKIM (try common selectors) ---
        found_dkim = []
        for sel in DKIM_SELECTORS:
            recs = _dig_txt(f"{sel}._domainkey.{domain}")
            if any("v=DKIM1" in r or "p=" in r for r in recs):
                found_dkim.append(sel)
        rep.records["dkim_selectors"] = found_dkim
        if not found_dkim:
            rep.findings.append(EmailFinding("DKIM", "LOW",
                "No DKIM found on common selectors (a different selector may be in use)."))

        # --- MX (bilgi) ---
        rep.records["mx"] = _dig(domain, "MX")
        log.info("Email security audit (%s): %d findings.", domain, len(rep.findings))
        return rep
