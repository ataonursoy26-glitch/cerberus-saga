"""
config/database.py
Asynchronous PostgreSQL (asyncpg) and Redis connection pool management.
Includes retry logic for failure cases.

NOTE: Demo mode does NOT require a database. This module is only used in
SaaS/MSSP deployments and degrades gracefully if the libraries are missing.
"""
from __future__ import annotations

import asyncio
import logging

from config.settings import DATABASE

log = logging.getLogger("cerberus.db")

try:
    import asyncpg
except ImportError:
    asyncpg = None

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None


class ConnectionManager:
    """Singleton layer that manages the PostgreSQL and Redis pools."""

    def __init__(self) -> None:
        self.pg_pool = None
        self.redis = None

    async def connect(self, retries: int = 3) -> None:
        for attempt in range(1, retries + 1):
            try:
                if asyncpg and self.pg_pool is None:
                    self.pg_pool = await asyncpg.create_pool(DATABASE["postgres_dsn"])
                    log.info("PostgreSQL havuzu kuruldu.")
                if aioredis and self.redis is None:
                    self.redis = aioredis.from_url(DATABASE["redis_url"])
                    log.info("Redis connection established.")
                return
            except Exception as exc:  # noqa: BLE001
                log.warning("DB connection attempt %d/%d failed: %s", attempt, retries, exc)
                await asyncio.sleep(2 ** attempt)
        log.warning("Database unavailable; falling back to in-memory mode (sufficient for the demo).")

    async def close(self) -> None:
        if self.pg_pool:
            await self.pg_pool.close()
        if self.redis:
            await self.redis.close()


manager = ConnectionManager()
