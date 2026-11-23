"""
utils/cryptography.py
Data encryption layer - AES-256-GCM (Blueprint Volume 1, utils).

Encrypts report/client data stored on disk (encryption at rest).
Uses real AES-256-GCM when the 'cryptography' library is installed; otherwise
it is disabled with a clear warning (it NEVER silently falls back to weak crypto).
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("cerberus.crypto")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class VaultCipher:
    """At-rest encryption with AES-256-GCM."""

    def __init__(self, key: bytes | None = None) -> None:
        if not _AVAILABLE:
            raise RuntimeError(
                "The 'cryptography' library is not installed. "
                "Add it with pip install cryptography (no fallback to weak encryption)."
            )
        self.key = key or AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: bytes, aad: bytes = b"cerberus") -> bytes:
        nonce = os.urandom(12)
        ct = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        return nonce + ct  # prepend the nonce to the ciphertext

    def decrypt(self, blob: bytes, aad: bytes = b"cerberus") -> bytes:
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(self.key).decrypt(nonce, ct, aad)


def is_available() -> bool:
    return _AVAILABLE
