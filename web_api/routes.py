"""
web_api/routes.py
Scan workflow and report download routes (Blueprint Volume 3, Module 3).
Helper router that can be mounted on the main.py app.
"""
from __future__ import annotations

from pathlib import Path

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import FileResponse
except ImportError as exc:
    raise RuntimeError("fastapi gerekli: pip install -r requirements.txt") from exc

router = APIRouter(prefix="/api/v1")


@router.get("/reports")
async def list_reports() -> dict:
    reports = sorted(Path("reports").glob("cerberus_*.html"), reverse=True)
    return {"reports": [r.name for r in reports]}


@router.get("/reports/{name}")
async def download_report(name: str):
    path = Path("reports") / name
    if not path.exists() or ".." in name:
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(str(path))
