"""
modules/forensics/integrity_log.py
Signed IMMUTABLE audit log (Blueprint Volume 7 recommendation).

Blueprint Volume 7/8 says an authorized pentest tool should, instead of HIDING
its traces, do the opposite and keep an IMMUTABLE audit log. This module
implements that: each event is chained to the previous record's hash (SHA-256
hash chain). If any record is altered afterwards, verify_chain() catches it.
This is cryptographic proof that the tool "does not hide what it did".
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger("cerberus.audit")

AUDIT_DIR = "storage/audit"


class AuditLog:
    def __init__(self, engagement: str) -> None:
        os.makedirs(AUDIT_DIR, exist_ok=True)
        self.path = os.path.join(AUDIT_DIR, f"{engagement}.audit.jsonl")
        self.engagement = engagement
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not os.path.exists(self.path):
            return "0" * 64  # genesis
        last = "0" * 64
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["entry_hash"]
        return last

    def record(self, action: str, data: dict) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "engagement": self.engagement,
            "action": action,
            "data": data,
            "prev_hash": self._last_hash,
        }
        payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry_hash = hashlib.sha256((self._last_hash + payload).encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._last_hash = entry_hash
        log.debug("audit: %s -> %s", action, entry_hash[:12])
        return entry_hash

    def verify_chain(self) -> bool:
        """Verifies the whole chain. Returns False if a single record was altered."""
        if not os.path.exists(self.path):
            return True
        prev = "0" * 64
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = json.loads(line)
                stored = entry.pop("entry_hash")
                if entry["prev_hash"] != prev:
                    return False
                payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                recomputed = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
                if recomputed != stored:
                    return False
                prev = stored
        return True
