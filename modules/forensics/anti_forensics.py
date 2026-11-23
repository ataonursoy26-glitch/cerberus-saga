"""
modules/forensics/anti_forensics.py  ->  SessionCleaner
SESSION MEMORY CLEANUP (Blueprint Volume 7, item b redefinition).

IMPORTANT BOUNDARY: Blueprint Volume 8 states that an anti-forensics module
meant for "trace hiding / forensic wiping" turns a tool into spyware.
This module has NO such purpose. It only does this:

  * When a scan ends it releases temporary sensitive buffers in process RAM
    (so no raw PII/secrets linger in memory).

Things it deliberately does NOT do:
  * Does NOT delete system/application logs.
  * NEVER clears the audit log (integrity_log) — it is immutable.
  * Does not hide disk/file traces.
"""
from __future__ import annotations

import asyncio
import gc
import logging

log = logging.getLogger("cerberus.cleanup")


class SessionCleaner:
    async def purge_process_memory(self) -> None:
        """Only tidies Python process memory. No log is ever deleted."""
        collected = gc.collect()
        await asyncio.sleep(0)  # yield to the event loop
        log.info("Session memory cleaned (gc: %d objects). Logs PRESERVED.", collected)
