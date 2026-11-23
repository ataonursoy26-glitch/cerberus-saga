"""
modules/offensive/jwt_analyzer.py
JWT (JSON Web Token) weakness analysis — offline, non-destructive.

Decodes a token and looks for forge/bypass risks:
  * alg=none        -> signature verification can be skipped (token can be forged) [CRITICAL]
  * weak HS256 secret -> if the signature is CRACKED via a common-secret list, the token can be forged [CRITICAL]
  * no exp / no expiry -> a stolen token is valid forever [MEDIUM]
  * expired            -> informational [INFO]
  * sensitive claim (role/admin/is_admin) -> privilege-escalation surface [LOW]
Analyzes only the given token text; it makes no network calls.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger("cerberus.jwt")

COMMON_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt", "jwtsecret", "key",
    "admin", "test", "qwerty", "supersecret", "secretkey", "s3cr3t", "token",
    "your-256-bit-secret", "mysecret", "default", "root", "pass",
]


@dataclass
class JWTFinding:
    check: str
    severity: str
    detail: str


@dataclass
class JWTReport:
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    cracked_secret: str = ""


def _b64d(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


class JWTAnalyzer:
    def analyze(self, token: str) -> JWTReport:
        rep = JWTReport()
        token = token.strip()
        parts = token.split(".")
        if len(parts) != 3:
            rep.findings.append(JWTFinding("format", "INFO", "Not a valid JWT structure (3 parts expected)."))
            return rep
        try:
            rep.header = json.loads(_b64d(parts[0]))
            rep.payload = json.loads(_b64d(parts[1]))
        except Exception as exc:  # noqa: BLE001
            rep.findings.append(JWTFinding("decode", "INFO", f"Could not decode: {str(exc)[:50]}"))
            return rep

        alg = str(rep.header.get("alg", "")).lower()

        # alg=none
        if alg in ("none", ""):
            rep.findings.append(JWTFinding("alg_none", "CRITICAL",
                "alg=none: with no signature verification the token can be fully forged."))

        # weak HS256 secret (crack the signature)
        if alg.startswith("hs"):
            signing_input = (parts[0] + "." + parts[1]).encode()
            try:
                sig = _b64d(parts[2])
            except Exception:  # noqa: BLE001
                sig = b""
            digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                      "hs512": hashlib.sha512}.get(alg, hashlib.sha256)
            for secret in COMMON_SECRETS:
                calc = hmac.new(secret.encode(), signing_input, digest).digest()
                if hmac.compare_digest(calc, sig):
                    rep.cracked_secret = secret
                    rep.findings.append(JWTFinding("weak_secret", "CRITICAL",
                        f"HS256 secret is weak and CRACKED ('{secret}') — an attacker can forge valid tokens."))
                    break

        # exp
        exp = rep.payload.get("exp")
        if exp is None:
            rep.findings.append(JWTFinding("no_exp", "MEDIUM",
                "No exp (expiry): a stolen token stays valid indefinitely."))
        elif isinstance(exp, (int, float)) and exp < time.time():
            rep.findings.append(JWTFinding("expired", "INFO", "Token has expired."))

        # hassas claim
        for claim in ("role", "roles", "is_admin", "admin", "scope", "permissions"):
            if claim in rep.payload:
                rep.findings.append(JWTFinding("sensitive_claim", "LOW",
                    f"Authorization claim present: '{claim}={rep.payload[claim]}' — privilege escalation if forgeable."))
                break

        if not rep.findings:
            rep.findings.append(JWTFinding("ok", "INFO", "No obvious JWT weakness found."))
        log.info("JWT analysis: alg=%s, %d findings.", alg, len(rep.findings))
        return rep
