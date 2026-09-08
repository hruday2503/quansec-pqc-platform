"""Small lifecycle helpers used by the API and workers."""

import asyncio
import logging
from collections.abc import Awaitable, Callable

from core.database import close_pool, get_pool

TaskFactory = tuple[str, Callable[[], Awaitable[None]]]


async def require_database() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        if await conn.fetchval("SELECT 1") != 1:
            raise RuntimeError("database readiness check failed")


async def run_worker(service: str, factories: list[TaskFactory]) -> None:
    """Run worker coroutines together; any unexpected exit fails the container."""
    logger = logging.getLogger(f"quansec.{service}")
    await require_database()
    tasks = [asyncio.create_task(factory(), name=name) for name, factory in factories]
    logger.info("%s ready: %s", service, ", ".join(t.get_name() for t in tasks))
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        task = next(iter(done))
        if task.cancelled():
            raise RuntimeError(f"{task.get_name()} stopped unexpectedly")
        error = task.exception()
        if error:
            raise error
        raise RuntimeError(f"{task.get_name()} returned unexpectedly")
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await close_pool()
