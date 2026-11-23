"""
modules/posture.py
Security posture scoring + tracking over time (snapshot & diff).

  * score_findings(sections) -> (score 0-100, letter grade, severity counts)
  * save_snapshot(...)        -> archives every assessment as JSON
  * diff_last(target)         -> new/resolved findings between the last two snapshots

Scoring weights (each finding is subtracted from the score):
  CRITICAL -40, HIGH -20, MEDIUM -8, LOW -2, INFO 0  (base 100, floor 0)
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}
SNAP_DIR = Path("storage/assessments")


def _sev(f) -> str:
    return str((f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "INFO")) or "INFO").upper()


def score_findings(sections: list[dict]) -> tuple[int, str, dict]:
    counts = {k: 0 for k in WEIGHTS}
    penalty = 0
    for sec in sections:
        for f in sec.get("findings", []):
            s = _sev(f)
            counts[s] = counts.get(s, 0) + 1
            penalty += WEIGHTS.get(s, 0)
    score = max(0, 100 - penalty)
    grade = ("A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70
             else "C" if score >= 55 else "D" if score >= 40 else "F")
    return score, grade, counts


def _safe(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target.split("://")[-1])


def save_snapshot(target: str, sections: list[dict], stack: dict) -> Path:
    score, grade, counts = score_findings(sections)
    d = SNAP_DIR / _safe(target)
    d.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    snap = {"target": target, "ts": ts, "score": score, "grade": grade,
            "counts": counts, "stack": stack, "sections": sections}
    fp = d / f"{ts}.json"
    fp.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    return fp


def list_snapshots(target: str) -> list[dict]:
    d = SNAP_DIR / _safe(target)
    if not d.exists():
        return []
    out = []
    for fp in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(fp.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    return out


def _fkey(f: dict) -> str:
    return f"{f.get('area','')}|{f.get('detail','')}"


def diff_last(target: str) -> dict:
    snaps = list_snapshots(target)
    if len(snaps) < 2:
        return {"enough": False, "count": len(snaps)}
    prev, cur = snaps[-2], snaps[-1]
    prev_f = {_fkey(f) for s in prev["sections"] for f in s["findings"]}
    cur_f = {_fkey(f) for s in cur["sections"] for f in s["findings"]}
    return {
        "enough": True,
        "prev_grade": prev["grade"], "cur_grade": cur["grade"],
        "prev_score": prev["score"], "cur_score": cur["score"],
        "new": sorted(cur_f - prev_f),
        "resolved": sorted(prev_f - cur_f),
    }
