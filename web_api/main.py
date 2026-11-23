"""
web_api/main.py
Enterprise SaaS API gateway (Blueprint Volume 3, Module 3).

Closes the CRITICAL gap identified in Blueprint Volume 7:
the old version only checked payment status. This version ALSO verifies,
BEFORE scanning, that the target is inside the authorization scope (scope.yaml).
So a paying customer cannot scan a domain they do not own.
"""
from __future__ import annotations

import asyncio
import logging

try:
    from fastapi import FastAPI, HTTPException, status
    from pydantic import BaseModel
except ImportError as exc:  # clear error if fastapi is not installed
    raise RuntimeError("web_api requires 'fastapi' and 'pydantic': pip install -r requirements.txt") from exc

from core.orchestrator import CerberusOrchestrator
from core.scope_guard import is_in_scope

log = logging.getLogger("cerberus.api")

app = FastAPI(title="Cerberus SaaS API Gateway", version="2026.4")


class ScanRequest(BaseModel):
    domain: str
    stripe_payment_status: str  # paid / unpaid


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "mode": "authorized-defensive"}


@app.post("/api/v1/start-scan", status_code=202)
async def start_scan(payload: ScanRequest) -> dict:
    # --- 1) Authorization gate (closes the Volume 7 gap) ----------------
    if not is_in_scope(payload.domain):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"'{payload.domain}' is outside the authorization scope (scope.yaml). "
                    "Domain ownership verification is required before scanning."),
        )
    # --- 2) Payment verification (original check) ----------------------
    if payload.stripe_payment_status != "paid":
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Subscription and payment verification failed.",
        )
    # --- 3) Queue the asynchronous scan ---------------------------------
    orchestrator = CerberusOrchestrator(payload.domain)
    asyncio.create_task(orchestrator.run_pipeline())
    return {
        "status": "Scan In Progress",
        "target": payload.domain,
        "message": "Job queued. A report will be generated when it completes.",
    }
