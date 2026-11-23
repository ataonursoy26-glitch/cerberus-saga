"""
modules/crypto/exchange_guard.py
Crypto exchange / wallet security detection layer (Binance etc. focused).

IMPORTANT BOUNDARY: This module does NOT scan/attack an exchange. It only detects
crypto secrets leaked in TEXT/FILES and measures fake-exchange (phishing) domain
similarity. Entirely local, defensive purpose.

Tespit ettikleri:
  1. Exchange API keys (Binance-style 64-char), only with a context anchor
  2. Seed phrase / kurtarma kelimeleri (BIP-39 sezgisel: 12/15/18/21/24 kelime)
  3. Wallet private key (64-hex, with '0x' or an anchor word)
  4. Fake-exchange domain (typosquat): binance/coinbase/kraken... similarity
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

log = logging.getLogger("cerberus.crypto")

# --- 1) Exchange API key (requires context; otherwise 64-alnum gives too many false positives) ---
_EXCHANGE_CTX = re.compile(r"(binance|bybit|okx|kucoin|coinbase|kraken|api[_-]?key|api[_-]?secret|secret[_-]?key)", re.I)
_KEY64 = re.compile(r"\b[A-Za-z0-9]{64}\b")

# --- 2) Seed phrase: consecutive lowercase words ---
_WORDS = re.compile(r"\b([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})\b")
_SEED_CTX = re.compile(r"(seed|mnemonic|recovery\s*phrase|backup\s*phrase|kurtarma)", re.I)
# A small validation set of common BIP-39 words (confidence booster)
_BIP39_SAMPLE = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "access", "account", "achieve", "across", "action", "actor", "adapt", "add",
    "legal", "lemon", "zebra", "zero", "zone", "wealth", "winner", "wisdom",
    "rocket", "salmon", "scissors", "ozone", "uncle", "typical", "trophy", "van",
}

# --- 3) Wallet private key ---
_HEX64 = re.compile(r"\b(?:0x)?[0-9a-fA-F]{64}\b")
_WALLET_CTX = re.compile(r"(private\s*key|priv[_-]?key|wallet|cüzdan|0x)", re.I)

# --- 4) Sahte-borsa domain (typosquat) ---
KNOWN_EXCHANGES = ["binance.com", "coinbase.com", "kraken.com", "bybit.com",
                   "okx.com", "kucoin.com", "crypto.com", "bitfinex.com"]


@dataclass
class CryptoFinding:
    kind: str          # EXCHANGE_API_KEY / SEED_PHRASE / WALLET_PRIVATE_KEY / PHISHING_DOMAIN
    severity: str
    detail: str
    masked: str = ""


@dataclass
class CryptoReport:
    findings: list = field(default_factory=list)


def _mask(v: str) -> str:
    v = v.strip()
    return "*" * len(v) if len(v) <= 4 else v[:2] + "*" * (len(v) - 4) + v[-2:]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class ExchangeGuard:
    def scan_text(self, text: str) -> CryptoReport:
        rep = CryptoReport()

        # 1) Exchange API key — only if an anchor is nearby
        for m in _KEY64.finditer(text):
            window = text[max(m.start() - 40, 0):min(m.end() + 40, len(text))]
            if _EXCHANGE_CTX.search(window):
                rep.findings.append(CryptoFinding(
                    "EXCHANGE_API_KEY", "CRITICAL",
                    "An exchange API key appears to be hardcoded (64-char + exchange context).",
                    _mask(m.group(0))))

        # 2) Seed phrase
        for m in _WORDS.finditer(text):
            phrase = m.group(1)
            words = phrase.split()
            if len(words) not in (12, 15, 18, 21, 24):
                continue
            window = text[max(m.start() - 50, 0):min(m.end() + 20, len(text))]
            hits = sum(1 for w in words if w in _BIP39_SAMPLE)
            has_ctx = bool(_SEED_CTX.search(window))
            if has_ctx or hits >= 2:
                sev = "CRITICAL"
                rep.findings.append(CryptoFinding(
                    "SEED_PHRASE", sev,
                    f"Possible wallet recovery phrase ({len(words)} words"
                    + (", with a context word" if has_ctx else "") + ").",
                    f"{words[0]} … {words[-1]}"))

        # 3) Wallet private key
        for m in _HEX64.finditer(text):
            window = text[max(m.start() - 30, 0):min(m.end() + 30, len(text))]
            if _WALLET_CTX.search(window):
                rep.findings.append(CryptoFinding(
                    "WALLET_PRIVATE_KEY", "CRITICAL",
                    "A wallet private key appears to be hardcoded (64-hex + wallet context).",
                    _mask(m.group(0))))
        return rep

    def check_phishing_domain(self, domain: str) -> CryptoFinding | None:
        """Whether a domain is dangerously similar to known exchanges."""
        d = domain.lower().strip().split("/")[0]
        for real in KNOWN_EXCHANGES:
            if d == real:
                return CryptoFinding("PHISHING_DOMAIN", "INFO",
                                     f"'{d}' is a real/known exchange domain.", d)
            brand = real.split(".")[0]
            dist = _levenshtein(d.split(".")[0], brand)
            if 0 < dist <= 2 or (brand in d and d != real):
                return CryptoFinding(
                    "PHISHING_DOMAIN", "HIGH",
                    f"'{d}' closely resembles '{real}' — possible fake/phishing exchange.", d)
        return None
