"""
modules/offensive/tls_scan.py
TLS protocol version scan (authorized, read-only).

Detects which TLS versions the target accepts by handshaking with each one.
If old/weak versions (TLS 1.0 / 1.1, SSLv3) are enabled, that is a
downgrade/POODLE/BEAST-class risk. Only connects; sends no data.
"""
from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.tlsscan")

_VERSIONS = [
    ("TLSv1", ssl.TLSVersion.TLSv1, "HIGH"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "HIGH"),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "INFO"),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "INFO"),
]


@dataclass
class TLSScanFinding:
    severity: str
    detail: str


@dataclass
class TLSScanReport:
    host: str
    supported: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


def assess_protocols(supported: dict) -> list:
    """supported: {version: bool} -> findings (pure, testable)."""
    out = []
    if supported.get("TLSv1"):
        out.append(TLSScanFinding("HIGH", "TLS 1.0 enabled — deprecated (BEAST/POODLE class)."))
    if supported.get("TLSv1.1"):
        out.append(TLSScanFinding("HIGH", "TLS 1.1 enabled — deprecated, disable it."))
    if not supported.get("TLSv1.2") and not supported.get("TLSv1.3"):
        out.append(TLSScanFinding("HIGH", "Modern TLS (1.2/1.3) does not appear to be supported."))
    if supported.get("TLSv1.3") and not supported.get("TLSv1") and not supported.get("TLSv1.1"):
        out.append(TLSScanFinding("INFO", "TLS 1.3 available, old versions disabled — good configuration."))
    if not out:
        out.append(TLSScanFinding("INFO", "TLS version configuration is reasonable."))
    return out


class TLSScanner:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.host = target.split("://")[-1].split("/")[0].split(":")[0]

    def _supports(self, ver: ssl.TLSVersion, timeout: int = 6) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except ValueError:
            return False
        try:
            with socket.create_connection((self.host, 443), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=self.host):
                    return True
        except Exception:  # noqa: BLE001
            return False

    def run(self) -> TLSScanReport:
        rep = TLSScanReport(host=self.host)
        for name, ver, _sev in _VERSIONS:
            rep.supported[name] = self._supports(ver)
        rep.findings = assess_protocols(rep.supported)
        log.info("TLS scan (%s): %s", self.host,
                 ",".join(k for k, v in rep.supported.items() if v))
        return rep
