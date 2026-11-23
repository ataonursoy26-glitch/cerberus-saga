"""
modules/osint/shodan_intel.py
Shodan / Censys passive asset analysis (Blueprint Volume 2, OSINT module).

Passive recon: pulls historical scan records from third-party intelligence
pools without sending active packets to the target. Without an API key it
falls back to "offline/simulated" mode (enough for the demo).
"""
from __future__ import annotations

import logging

from config.settings import API_KEYS
from core.scope_guard import assert_in_scope

log = logging.getLogger("cerberus.osint")

try:
    import shodan  # type: ignore
except ImportError:
    shodan = None


class ShodanScanner:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or API_KEYS.get("SHODAN", "")

    async def fetch(self, target: str) -> dict:
        assert_in_scope(target)
        if shodan and self.api_key:
            try:
                api = shodan.Shodan(self.api_key)
                host = api.host(target)  # synchronous library; no network access in the demo
                return {
                    "source": "shodan-live",
                    "ip": host.get("ip_str"),
                    "org": host.get("org"),
                    "open_ports": host.get("ports", []),
                    "tags": host.get("tags", []),
                }
            except Exception as exc:  # noqa: BLE001
                log.warning("Shodan query failed (%s); falling back to simulated mode.", exc)
        log.info("No Shodan API key -> passive OSINT simulation.")
        return {
            "source": "simulated",
            "note": "SHODAN_API_KEY is not set. Add the environment variable for live passive recon.",
            "target": target,
        }
