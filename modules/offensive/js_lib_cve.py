"""
modules/offensive/js_lib_cve.py
Client-side JS library version + CVE detection (authorized, read-only).

Extracts the versions of libraries such as jQuery, Bootstrap, Lodash and
AngularJS from the page/linked scripts and matches known vulnerable ranges.
Outdated frontend libraries (DOM XSS, prototype pollution) are a real risk.
Read-only. Backs off when rate-limited.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.jslib")


def _ver(s: str):
    nums = [int(x) for x in s.split(".")[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


# (library, regex, safe-lower-bound, cve, severity, description)
LIB_RULES = [
    ("jQuery", r"jquery[/-]?v?(\d+\.\d+\.\d+)", (3, 5, 0),
     "CVE-2020-11022/11023", "MEDIUM", "jQuery <3.5.0 — htmlPrefilter DOM XSS."),
    ("Bootstrap", r"bootstrap[/-]?v?(\d+\.\d+\.\d+)", (4, 3, 1),
     "CVE-2019-8331", "MEDIUM", "Bootstrap <4.3.1 — tooltip/popover XSS."),
    ("Lodash", r"lodash[/-]?v?(\d+\.\d+\.\d+)", (4, 17, 21),
     "CVE-2021-23337", "HIGH", "Lodash <4.17.21 — command injection/prototype pollution."),
    ("AngularJS", r"angular[.-]?js[/-]?v?(\d+\.\d+\.\d+)|angular[/-]?v?(1\.\d+\.\d+)", (1, 8, 0),
     "multiple", "MEDIUM", "AngularJS 1.x (EOL) — sandbox bypass/DOM XSS."),
]


@dataclass
class LibReport:
    target: str
    inconclusive: bool = False
    libraries: list = field(default_factory=list)
    findings: list = field(default_factory=list)


def classify(text: str) -> tuple[list, list]:
    libs, findings = [], []
    low = text.lower()
    for name, pattern, safe, cve, sev, desc in LIB_RULES:
        m = re.search(pattern, low)
        if not m:
            continue
        ver = next((g for g in m.groups() if g), None)
        if not ver:
            continue
        libs.append({"lib": name, "version": ver})
        try:
            if _ver(ver) < safe:
                findings.append({"lib": name, "version": ver, "severity": sev,
                                 "detail": f"{desc} (detected: {ver}, {cve})."})
        except Exception:  # noqa: BLE001
            pass
    return libs, findings


class JSLibCVE:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> LibReport:
        rep = LibReport(target=self.target)
        r = request(self.target, read_bytes=800_000)
        if r.status in (429, 403, 503) or r.status == 0:
            rep.inconclusive = True
            return rep
        rep.libraries, rep.findings = classify(r.body or "")
        if not rep.findings:
            rep.findings.append({"lib": "-", "version": "", "severity": "INFO",
                                 "detail": "No vulnerable JS library version detected."})
        log.info("JS library CVE (%s): %d libraries, %d findings.",
                 self.target, len(rep.libraries), len(rep.findings))
        return rep
