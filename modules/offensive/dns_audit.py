"""
modules/offensive/dns_audit.py
DNS security audit (authorized, passive queries).

  * Zone transfer (AXFR): a misconfigured name server can hand out ALL DNS records
    (every subdomain) -> critical information disclosure. Read-only query.
  * CAA: restricts which CAs may issue certificates; missing = rogue-certificate surface.
  * DNSSEC: an unsigned zone means DNS spoofing/cache poisoning risk.
Only runs public DNS queries with dig; never attacks the target.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger("cerberus.dnssec")


@dataclass
class DNSFinding:
    check: str
    severity: str
    detail: str


@dataclass
class DNSReport:
    domain: str
    nameservers: list = field(default_factory=list)
    findings: list = field(default_factory=list)


def _dig(args: list[str], timeout: int = 10) -> str:
    if not shutil.which("dig"):
        return ""
    try:
        return subprocess.run(["dig", "+short", *args] if "+short" not in args and "AXFR" not in args
                              else ["dig", *args], capture_output=True, text=True, timeout=timeout).stdout
    except Exception:  # noqa: BLE001
        return ""


class DNSAuditor:
    def __init__(self, domain: str) -> None:
        self.domain = domain.split("://")[-1].split("/")[0].split(":")[0]

    def run(self) -> DNSReport:
        rep = DNSReport(domain=self.domain)
        ns = [l.strip(".") for l in _dig(["+short", "NS", self.domain]).split() if l.strip()]
        rep.nameservers = ns

        # Zone transfer attempt (against each NS)
        for server in ns[:4]:
            out = _dig(["AXFR", self.domain, f"@{server}"], timeout=12)
            # A successful AXFR returns many record lines
            record_lines = [l for l in out.splitlines() if "\tIN\t" in l or " IN " in l]
            if len(record_lines) > 3 and "Transfer failed" not in out and "connection timed out" not in out.lower():
                rep.findings.append(DNSFinding("AXFR", "CRITICAL",
                    f"Zone transfer OPEN ({server}) — {len(record_lines)} DNS records exposed."))
                break

        # CAA
        if not _dig(["+short", "CAA", self.domain]).strip():
            rep.findings.append(DNSFinding("CAA", "LOW",
                "No CAA record — which CAs may issue certificates is unrestricted."))
        # DNSSEC
        dnskey = _dig(["+short", "DNSKEY", self.domain]).strip()
        if not dnskey:
            rep.findings.append(DNSFinding("DNSSEC", "LOW",
                "No DNSSEC (DNSKEY) — DNS spoofing/cache poisoning risk."))

        if not rep.findings:
            rep.findings.append(DNSFinding("ok", "INFO", "No obvious DNS security issues found."))
        log.info("DNS audit (%s): %d NS, %d findings.", self.domain, len(ns), len(rep.findings))
        return rep
