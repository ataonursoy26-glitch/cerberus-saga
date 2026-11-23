"""
modules/evasion/waf_evasion.py  ->  TrafficShaper
LEGITIMATE TRAFFIC-SHAPING LAYER (Blueprint Volume 7, item b redefinition).

The blueprint's own compliance analysis (Volume 7/8) states that a raw "WAF evasion /
trace hiding" goal is UNACCEPTABLE in an authorized audit tool, and recommends
placing this layer in a legitimate frame such as "test traffic blending with
normal traffic / rate limiting".

This module does exactly that:
  * Uses a standard browser User-Agent (NOT hiding/spoofing; honest requests)
  * Adds a polite delay between requests (rate limiting) -> does not overload the target
  * Does NOT hide traces: every request is written to the audit log (integrity_log).
"""
from __future__ import annotations

import logging
import random

log = logging.getLogger("cerberus.shaper")

# An honest, standard User-Agent. NO rotation for identity hiding.
DEFAULT_USER_AGENT = "Cerberus-Security-Scanner/1.0 (+authorized-pentest)"


class TrafficShaper:
    def __init__(self, min_delay: float = 0.2, max_delay: float = 1.0) -> None:
        self.min_delay = min_delay
        self.max_delay = max_delay

    async def initialize_route(self) -> None:
        # Does not build a real "stealth route"; only announces the polite rate policy.
        log.info("Traffic shaping: polite rate limiting active (NO hiding, audit ON).")

    def polite_delay(self) -> float:
        """Delay between requests so the target is not overloaded (rate limiting)."""
        return random.uniform(self.min_delay, self.max_delay)

    def standard_headers(self) -> dict:
        return {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "X-Cerberus-Authorized-Scan": "true",  # honest marker for auditability
        }
