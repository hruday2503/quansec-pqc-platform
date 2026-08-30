"""Database migration runner shared by the CLI and container init job."""

import logging
from pathlib import Path

import asyncpg

logger = logging.getLogger("quansec.migrations")


async def run_migrations(pool: asyncpg.Pool) -> None:
    """Apply every checked-in migration and fail the process on an error."""
    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    async with pool.acquire() as conn:
        for sql_file in sorted(migrations_dir.glob("*.sql")):
            logger.info("Running migration: %s", sql_file.name)
            await conn.execute(sql_file.read_text())
