"""Independent policy API and alert evaluation service."""

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.database import close_pool, get_pool
from core.host_control import host_control_request
from protocols.alerts.router import alerts_loop
from protocols.ipsec.policy import router as ipsec_policy_router
from protocols.ssh.policy import router as ssh_policy_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("SELECT 1")
    host = await asyncio.to_thread(host_control_request, "status", {})
    required = {item.strip() for item in os.getenv(
        "QUANSEC_REQUIRED_POLICY_TARGETS", "strongswan,openssh_pqc"
    ).split(",") if item.strip()}
    missing = sorted(name for name in required if not host.get(name))
    if missing:
        raise RuntimeError(f"real policy targets are unavailable: {', '.join(missing)}")
    alerts = asyncio.create_task(alerts_loop(), name="policy-alert-evaluator")
    try:
        yield
    finally:
        alerts.cancel()
        await asyncio.gather(alerts, return_exceptions=True)
        await close_pool()


app = FastAPI(title="QUANSEC Policy Engine", version="2.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:443"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ipsec_policy_router)
app.include_router(ssh_policy_router)


@app.get("/health")
async def health():
    host = await asyncio.to_thread(host_control_request, "status", {})
    return {"status": "ok", "service": "policy-engine", "host_control": host}
