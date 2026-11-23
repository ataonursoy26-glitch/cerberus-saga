"""
modules/web/tls_analyzer.py
TLS / certificate analysis.

Connects securely to the target's port 443 and reads the certificate it PRESENTS
and the negotiated TLS version: subject, issuer, validity, days to expiry, protocol
version, cipher suite. Read-only; runs only on in-scope targets.
"""
from __future__ import annotations

import datetime as _dt
import logging
import socket
import ssl
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.tls")


@dataclass
class TLSFinding:
    check: str
    severity: str
    detail: str


@dataclass
class TLSReport:
    host: str
    info: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


class TLSAnalyzer:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.host = target.split("://")[-1].split("/")[0].split(":")[0]

    def analyze(self, port: int = 443, timeout: int = 8) -> TLSReport:
        rep = TLSReport(host=self.host)
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    rep.info["tls_version"] = ssock.version()
                    rep.info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
        except ssl.SSLCertVerificationError as exc:
            rep.findings.append(TLSFinding("Certificate Validation", "HIGH",
                f"Certificate could not be validated: {str(exc)[:80]}"))
            return rep
        except Exception as exc:  # noqa: BLE001
            rep.findings.append(TLSFinding("Connection", "INFO", f"TLS connection failed: {str(exc)[:80]}"))
            return rep

        # Veren / konu
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        rep.info["issuer"] = issuer.get("organizationName", issuer.get("commonName", "?"))
        rep.info["subject"] = subject.get("commonName", "?")

        # Validity
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - _dt.datetime.utcnow()).days
                rep.info["expires"] = not_after
                rep.info["days_left"] = days
                if days < 0:
                    rep.findings.append(TLSFinding("Validity", "HIGH", "Certificate has EXPIRED."))
                elif days < 15:
                    rep.findings.append(TLSFinding("Validity", "MEDIUM",
                        f"Certificate expires in {days} days — time to renew."))
            except ValueError:
                pass

        # Weak protocol
        ver = rep.info.get("tls_version", "")
        if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
            rep.findings.append(TLSFinding("Protokol", "HIGH",
                f"Old/weak protocol: {ver}. TLS 1.2+ should be used."))
        else:
            rep.info["protocol_ok"] = True

        log.info("TLS analysis (%s): %s, %d findings.", self.host, ver, len(rep.findings))
        return rep
