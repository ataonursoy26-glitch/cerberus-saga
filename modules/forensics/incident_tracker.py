"""
modules/forensics/incident_tracker.py
Incident response and unauthorized-access impact analysis (Blueprint Volume 14-17).

Analyzes the given access logs and presents unauthorized sessions, accessed
assets and possible data exposure to the analyst as a line-by-line
evidence chain. Only reads the given log; makes no changes to the system.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger("cerberus.incident")


@dataclass
class ImpactEvent:
    actor: str
    asset: str
    action: str
    severity: str


@dataclass
class IncidentReport:
    findings: List[ImpactEvent] = field(default_factory=list)


class IncidentTracker:
    SENSITIVE_ASSETS = ("users", "payments", "secrets", "admin", "backup")

    async def analyze(self, access_log: list[dict]) -> IncidentReport:
        report = IncidentReport()
        for e in access_log:
            if not e.get("authorized", True):
                asset = str(e.get("asset", "")).lower()
                sev = "CRITICAL" if any(s in asset for s in self.SENSITIVE_ASSETS) else "HIGH"
                report.findings.append(ImpactEvent(
                    actor=e.get("actor", "unknown"), asset=e.get("asset", ""),
                    action=e.get("action", ""), severity=sev))
        log.info("Incident response: %d unauthorized access events.", len(report.findings))
        return report
