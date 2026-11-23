"""
modules/social/deepfake_sim.py
Cyber-awareness / social-engineering SIMULATOR (Blueprint Volume 1, social).

IMPORTANT ETHICAL BOUNDARY: this module does NOT and cannot clone real voices/images.
It only produces sample phishing/vishing scenario TEXT for security AWARENESS
training; the goal is to help staff recognise these attacks.
It never produces content impersonating a real person and sends nothing to anyone.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cerberus.social")

AWARENESS_SCENARIOS = [
    {"vector": "phishing_email",
     "red_flags": ["urgency pressure", "spoofed sender domain", "unexpected attachment"],
     "training_note": "Staff: verify the sender address and the link before clicking."},
    {"vector": "vishing_call",
     "red_flags": ["IT support impersonation", "password/OTP request", "no callback number given"],
     "training_note": "The organisation never asks for a password/OTP over the phone."},
    {"vector": "mfa_fatigue",
     "red_flags": ["repeated push notifications", "requests late at night"],
     "training_note": "Unexpected MFA prompts must be denied and reported."},
]


class AwarenessSimulator:
    async def generate_training_scenarios(self) -> list[dict]:
        log.info("Awareness scenarios generated: %d (NO real cloning).",
                 len(AWARENESS_SCENARIOS))
        return AWARENESS_SCENARIOS
