"""
modules/offensive/ownership.py
Domain ownership verification (implementation of Blueprint Volume 7, item a).

BEFORE any active offensive scan, proves the target really belongs to the
user. Method (either one):
  1. HTTP: https://<domain>/.well-known/cerberus-verify.txt  containing the token
  2. DNS : <domain> TXT record   cerberus-verify=<token>

Because only the OWNER of the site/DNS can place this token, this
verification proves real control, unlike simply saying "it's mine".
Once verified, the domain is added to scope.yaml and scan commands are unlocked.
"""
from __future__ import annotations

import logging
import secrets
import shutil
import subprocess
from pathlib import Path

from config.settings import SCOPE_FILE, get_authorized_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.own")

TOKEN_DIR = Path("storage/ownership")


def _norm(domain: str) -> str:
    return domain.split("://")[-1].split("/")[0].split(":")[0].lower()


def token_for(domain: str) -> str:
    """Persistent per-domain verification token (generated if missing)."""
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    fp = TOKEN_DIR / (_norm(domain) + ".token")
    if fp.exists():
        return fp.read_text(encoding="utf-8").strip()
    token = "cerberus-verify=" + secrets.token_hex(16)
    fp.write_text(token, encoding="utf-8")
    return token


def check(domain: str) -> dict:
    """Has the token been placed via HTTP or DNS?"""
    domain = _norm(domain)
    token = token_for(domain)
    result = {"domain": domain, "token": token, "verified": False, "method": ""}

    # 1) HTTP well-known
    for scheme in ("https", "http"):
        r = request(f"{scheme}://{domain}/.well-known/cerberus-verify.txt", timeout=6)
        if r.status == 200 and token in (r.body or ""):
            result.update(verified=True, method="http")
            return result

    # 2) DNS TXT
    if shutil.which("dig"):
        try:
            out = subprocess.run(["dig", "+short", "TXT", domain],
                                 capture_output=True, text=True, timeout=8).stdout
            if token in out:
                result.update(verified=True, method="dns")
        except Exception:  # noqa: BLE001
            pass
    return result


def add_to_scope(domain: str) -> bool:
    """Adds a verified domain to the scope.yaml authorized_scope list."""
    domain = _norm(domain)
    if domain in get_authorized_scope():
        return True
    text = SCOPE_FILE.read_text(encoding="utf-8")
    lines = text.splitlines()
    out, inserted = [], False
    for line in lines:
        out.append(line)
        if line.strip().startswith("authorized_scope:") and not inserted:
            out.append(f'  - "{domain}"            # ownership verified')
            inserted = True
    SCOPE_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")
    return inserted
