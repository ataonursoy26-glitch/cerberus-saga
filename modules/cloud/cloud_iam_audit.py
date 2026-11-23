"""
modules/cloud/cloud_iam_audit.py
Cloud IAM misconfiguration / privilege escalation audit
(Blueprint Volume 1, cloud layer).

Statically inspects AWS/Azure/GCP IAM policy JSON; flags overly broad
permissions (wildcard action/resource, public trust relationships).
Never writes to or modifies a live cloud account; only reads the given policy.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cerberus.cloud")


class CloudIAMAuditor:
    async def audit_policy(self, policy: dict) -> list[dict]:
        findings = []
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = stmt.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources
            if "*" in actions:
                findings.append({"type": "WILDCARD_ACTION", "severity": "HIGH",
                                 "detail": "Policy allows all actions (*)."})
            if "*" in resources:
                findings.append({"type": "WILDCARD_RESOURCE", "severity": "HIGH",
                                 "detail": "Policy allows all resources (*)."})
            principal = stmt.get("Principal")
            if principal == "*" or principal == {"AWS": "*"}:
                findings.append({"type": "PUBLIC_TRUST", "severity": "CRITICAL",
                                 "detail": "Trust relationship is open to everyone (*)."})
        log.info("Cloud IAM audit: %d findings.", len(findings))
        return findings
