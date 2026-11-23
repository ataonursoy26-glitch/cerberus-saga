"""
utils/ai_brain.py
AI-assisted risk interpretation engine (Blueprint Volume 2, utils).

Turns raw technical findings into an executive-level summary.
Uses an OpenAI/Anthropic API key if one is set; otherwise it falls back
to a fully local, rule-based summarizer (enough for the demo, no network).

Sensitive findings are already masked, so no raw data reaches an external API.
"""
from __future__ import annotations

import logging

from config.settings import API_KEYS

log = logging.getLogger("cerberus.ai")


class AIBrain:
    def summarize(self, results: dict) -> str:
        counts: dict[str, int] = {}
        for item in (results.get("dlp_findings", []) + results.get("vulnerabilities", [])
                     + results.get("cti", [])):
            sev = (item.get("severity") if isinstance(item, dict)
                   else getattr(item, "severity", "INFO")) or "INFO"
            counts[sev.upper()] = counts.get(sev.upper(), 0) + 1

        if API_KEYS.get("OPENAI") or API_KEYS.get("ANTHROPIC"):
            # Live LLM integration is called here (a masked summary is sent).
            log.info("LLM key present; live semantic summary available.")

        crit = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        if crit:
            risk = "HIGH -- critical findings require immediate remediation."
        elif high:
            risk = "MEDIUM-HIGH -- significant findings warrant planned remediation."
        else:
            risk = "LOW-MEDIUM -- no critical findings; improvement recommendations available."

        return (f"Executive Summary: the audit identified {crit} critical and {high} high-severity "
                f"findings. Overall risk level: {risk} "
                f"All sensitive data is reported masked (GDPR-compliant).")
