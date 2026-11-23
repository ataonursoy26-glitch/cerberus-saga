"""
modules/offensive/tracker_audit.py
Third-party tracker / privacy audit (authorized, read-only).

Detects known tracking/analytics scripts on the page (Google Analytics, Meta Pixel,
TikTok, Hotjar, etc.). Their presence creates explicit-consent and privacy-policy
obligations under GDPR/KVKK. Technical awareness only,
not legal advice. Backs off on rate limits (429).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.tracker")

TRACKERS = {
    "Google Analytics": r"google-analytics\.com|gtag\(|googletagmanager\.com|ga\.js",
    "Meta/Facebook Pixel": r"connect\.facebook\.net|fbevents\.js|fbq\(",
    "TikTok Pixel": r"analytics\.tiktok\.com|ttq\.",
    "Hotjar": r"static\.hotjar\.com|hotjar\.com",
    "Microsoft Clarity": r"clarity\.ms",
    "Google Ads/DoubleClick": r"doubleclick\.net|googleadservices\.com",
    "LinkedIn Insight": r"snap\.licdn\.com",
    "Pinterest Tag": r"pintrk\(|ct\.pinterest\.com",
    "Hotspot/HubSpot": r"js\.hs-scripts\.com|hubspot",
}


@dataclass
class TrackerReport:
    target: str
    inconclusive: bool = False
    trackers: list = field(default_factory=list)
    findings: list = field(default_factory=list)


class TrackerAuditor:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> TrackerReport:
        rep = TrackerReport(target=self.target)
        r = request(self.target, read_bytes=600_000)
        if r.status in (429, 403, 503) or r.status == 0:
            rep.inconclusive = True
            return rep
        body = r.body or ""
        for name, pattern in TRACKERS.items():
            if re.search(pattern, body, re.I):
                rep.trackers.append(name)
        if rep.trackers:
            rep.findings.append({"severity": "LOW",
                "detail": f"{len(rep.trackers)} trackers detected: {', '.join(rep.trackers)}. "
                          "GDPR/KVKK: requires explicit consent (cookie banner) + listing in the privacy policy."})
        else:
            rep.findings.append({"severity": "INFO", "detail": "No known third-party trackers detected."})
        log.info("Tracker audit (%s): %d trackers.", self.target, len(rep.trackers))
        return rep
