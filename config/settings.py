"""
config/settings.py
API Gateway configuration, global environment variables, and the
AUTHORIZATION SCOPE loader (Blueprint Volume 2 + Volume 7).

Secrets are read from environment variables; never hardcoded.
scope.yaml provides the authorization scope on every call.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    import yaml  # pyyaml
except ImportError:  # graceful: fall back to a simple parser if yaml is missing
    yaml = None

BASE_DIR = Path(__file__).resolve().parent.parent
SCOPE_FILE = BASE_DIR / "scope.yaml"

# --- Third-party API keys (from environment; optional) ---------------------
API_KEYS = {
    "SHODAN": os.getenv("SHODAN_API_KEY", ""),
    "CENSYS_ID": os.getenv("CENSYS_API_ID", ""),
    "CENSYS_SECRET": os.getenv("CENSYS_API_SECRET", ""),
    "OPENAI": os.getenv("OPENAI_API_KEY", ""),
    "ANTHROPIC": os.getenv("ANTHROPIC_API_KEY", ""),
    "DEHASHED": os.getenv("DEHASHED_API_KEY", ""),
    "STRIPE": os.getenv("STRIPE_API_KEY", ""),
}

# --- Database / cache settings (optional; the demo does not need these) -----
DATABASE = {
    "postgres_dsn": os.getenv("POSTGRES_DSN", "postgresql://localhost/cerberus"),
    "redis_url": os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    "redis_pool_size": int(os.getenv("REDIS_POOL_SIZE", "10")),
}

# --- Operasyonel ayarlar -----------------------------------------------------
SETTINGS = {
    "mask_findings": True,          # Volume 8: findings are always masked
    "allow_external_exfil": False,  # Volume 8: no raw data is sent to external endpoints
    "audit_log_enabled": True,      # Volume 7: signed immutable audit log
    "max_scan_timeout": int(os.getenv("CERBERUS_SCAN_TIMEOUT", "300")),
}


def _fallback_parse_scope(text: str) -> dict:
    """Extracts only the authorized_scope list from scope.yaml when pyyaml is not installed."""
    scope: list[str] = []
    in_list = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("authorized_scope:"):
            in_list = True
            continue
        if in_list:
            if stripped.startswith("- "):
                scope.append(stripped[2:].split("#")[0].strip().strip('"\''))
            elif stripped and not line.startswith((" ", "\t")):
                break
    return {"authorized_scope": scope}


def load_scope() -> dict:
    """Reads scope.yaml and returns the authorization scope."""
    if not SCOPE_FILE.exists():
        raise FileNotFoundError(
            f"Authorization scope file not found: {SCOPE_FILE}. "
            "Per Blueprint Volume 7, scanning is not allowed without a scope file."
        )
    text = SCOPE_FILE.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text) or {}
    else:
        data = _fallback_parse_scope(text)
    data.setdefault("authorized_scope", [])
    return data


def get_authorized_scope() -> list[str]:
    """Returns only the list of allowed targets."""
    return load_scope().get("authorized_scope", [])
