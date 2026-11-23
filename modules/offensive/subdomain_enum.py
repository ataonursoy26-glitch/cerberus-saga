"""
modules/offensive/subdomain_enum.py
Subdomain discovery (DNS recon — passive, public records).

Resolves a domain's common subdomains via DNS. Only passive DNS
queries (anyone-can-dig); does NOT actively scan discovered hosts.
First step in mapping the attack surface.
"""
from __future__ import annotations

import concurrent.futures
import logging
import socket
from dataclasses import dataclass, field

log = logging.getLogger("cerberus.subenum")

WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns",
    "api", "api2", "dev", "staging", "stage", "test", "qa", "uat", "demo",
    "admin", "panel", "dashboard", "portal", "app", "apps", "m", "mobile",
    "vpn", "remote", "gateway", "gw", "proxy", "cdn", "static", "assets",
    "img", "images", "media", "files", "download", "ftp", "sftp", "git",
    "gitlab", "jenkins", "ci", "build", "docker", "registry", "k8s",
    "shop", "store", "checkout", "pay", "payment", "billing", "account",
    "login", "auth", "sso", "id", "blog", "news", "support", "help",
    "docs", "wiki", "status", "monitor", "grafana", "kibana", "db",
    "sql", "mysql", "postgres", "redis", "cache", "internal", "intranet",
    "corp", "vpn2", "old", "new", "beta", "alpha", "secure", "cpanel",
]


@dataclass
class SubReport:
    domain: str
    found: list = field(default_factory=list)
    tested: int = 0


def _resolve(name: str):
    try:
        return name, socket.gethostbyname(name)
    except Exception:  # noqa: BLE001
        return name, None


class SubdomainEnum:
    def __init__(self, domain: str) -> None:
        self.domain = domain.split("://")[-1].split("/")[0].split(":")[0]

    def run(self, max_workers: int = 20) -> SubReport:
        rep = SubReport(domain=self.domain)
        candidates = [f"{w}.{self.domain}" for w in WORDLIST]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for name, ip in ex.map(_resolve, candidates):
                rep.tested += 1
                if ip:
                    rep.found.append({"subdomain": name, "ip": ip})
        log.info("Subdomain discovery (%s): %d/%d resolved.", self.domain, len(rep.found), rep.tested)
        return rep
