"""Stateless QUANSEQ HTTP API. Collectors and policy execution live elsewhere."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.database import close_pool, get_pool
from protocols.alerts.router import router as alerts_router
from protocols.auth_api_keys import router as api_keys_router
from protocols.auth_router import router as auth_router
from protocols.failmode.router import router as failmode_router
from protocols.ipsec.attacks import router as attacks_router
from protocols.ipsec.router import router as ipsec_router
from protocols.ipsec.websocket import router as ws_router
from protocols.metrics.router import router as metrics_router
from protocols.scoring.router import router as scoring_router
from protocols.siem.router import router as siem_router
from protocols.ssh.ca import router as ssh_ca_router
from protocols.ssh.router import router as ssh_router
from protocols.ssh.ztaudit import router as zt_router
from protocols.tls.router import router as tls_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("SELECT 1")
    yield
    await close_pool()


app = FastAPI(title="QUANSEQ API", version="2.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:443"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (
    auth_router, api_keys_router, ipsec_router, ws_router, attacks_router,
    tls_router, ssh_router, ssh_ca_router, scoring_router, metrics_router,
    siem_router, alerts_router, failmode_router, zt_router,
):
    app.include_router(router)


@app.get("/health")
async def health():
    pool = await get_pool()
    async with pool.acquire() as conn:
        db_ok = await conn.fetchval("SELECT 1") == 1
    return {"status": "ok" if db_ok else "degraded", "service": "api", "database": db_ok}


@app.get("/")
async def root():
    return {"service": "QUANSEQ API", "version": "2.1.0", "docs": "/docs"}
