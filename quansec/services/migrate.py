"""One-shot database migration container."""

import asyncio
import logging

from core.database import close_pool, get_pool
from core.migrations import run_migrations


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    pool = await get_pool()
    try:
        await run_migrations(pool)
    finally:
        await close_pool()


if __name__ == "__main__":
    asyncio.run(main())
