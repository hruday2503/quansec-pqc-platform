"""
main.py — QUANSEC FastAPI application entry point.

Lifespan:
  startup  → run DB migrations, start background collector tasks
  shutdown → cancel collectors, close DB pool

Routers mounted:
  /api/ipsec   → protocols/ipsec/router.py  (Phase 1 — DONE)
  /api/tls     → protocols/tls/router.py    (Phase 2 — DONE)
  /api/ssh     → protocols/ssh/router.py    (Phase 3 — DONE)
  /api/vpn     → protocols/vpn/router.py    (Phase 4)

Run with:
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload

The TLS module needs its transport service running as a SEPARATE process:
  bash scripts/run_tls_service.sh
This app is a TLS client only; it never starts or owns that server.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.database import get_pool, close_pool
from protocols.ipsec.router import router as ipsec_router
from protocols.ssh.router import router as ssh_router
from protocols.tls.router import router as tls_router
from protocols.tls.collector import collect_loop as tls_collect_loop
from protocols.tls.settings import TlsConfigurationError, get_tls_settings
from protocols.ssh.ca import router as ssh_ca_router
from protocols.scoring.router import router as scoring_router
from protocols.metrics.router import router as metrics_router
from protocols.siem.router import router as siem_router
from protocols.alerts.router import router as alerts_router, alerts_loop
from protocols.failmode.router import router as failmode_router
from protocols.ssh.policy import router as ssh_policy_router
from protocols.ssh.ztaudit import router as zt_router, zt_collect_loop
from protocols.auth_router import router as auth_router
from protocols.auth_api_keys import router as api_keys_router
from protocols.ipsec.websocket import router as ws_router
from protocols.ipsec.policy import router as policy_router
from protocols.ipsec.attacks import router as attacks_router
from protocols.ipsec.collector import collect_loop as ipsec_collect_loop
from protocols.ssh.collector import collect_loop as ssh_collect_loop
from protocols.ipsec.events import event_listen_loop as ipsec_event_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("quansec.main")

_background_tasks: list[asyncio.Task] = []


async def run_migrations(pool: asyncpg.Pool):
    """Apply SQL migrations on startup."""
    import pathlib
    migrations_dir = pathlib.Path(__file__).parent / "migrations"
    sql_files = sorted(migrations_dir.glob("*.sql"))
    async with pool.acquire() as conn:
        for sql_file in sql_files:
            logger.info(f"Running migration: {sql_file.name}")
            sql = sql_file.read_text()
            try:
                await conn.execute(sql)
            except Exception as e:
                logger.error(f"Migration {sql_file.name} error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("QUANSEC starting up...")

    pool = await get_pool()
    await run_migrations(pool)
    logger.info("Database ready")

    # Start background collectors — one task per protocol
    ipsec_task = asyncio.create_task(ipsec_collect_loop(), name="ipsec-collector")
    _background_tasks.append(ipsec_task)
    logger.info("IPsec collector started")

    ipsec_ev_task = asyncio.create_task(ipsec_event_loop(), name="ipsec-events")
    _background_tasks.append(ipsec_ev_task)
    logger.info("IPsec lifecycle event listener started")

    # TLS — this app is a CLIENT of the TLS transport service, which runs as a
    # separate process (scripts/run_tls_service.sh). Startup validates the
    # configuration but never starts that server: a blocking thread-per-client
    # server does not belong beside an asyncio event loop, and a separate
    # process releases its listening socket unconditionally on exit.
    tls_settings = get_tls_settings()
    if tls_settings.enabled:
        try:
            for warning in tls_settings.validate():
                logger.warning(f"TLS: {warning}")
            logger.info(f"TLS config: {tls_settings.redacted()}")
        except TlsConfigurationError as e:
            # Not fatal: the rest of the platform must keep running, and the TLS
            # endpoints report the failure themselves.
            logger.error(f"TLS module misconfigured, endpoints will report 503: {e}")
        tls_task = asyncio.create_task(tls_collect_loop(), name="tls-collector")
        _background_tasks.append(tls_task)
        logger.info("TLS collector started")
    else:
        logger.info("TLS module disabled (QUANSEC_TLS_ENABLED=false)")

    ssh_task = asyncio.create_task(ssh_collect_loop(), name="ssh-collector")
    alerts_task = asyncio.create_task(alerts_loop(), name="alerts")
    _background_tasks.append(alerts_task)
    zt_task = asyncio.create_task(zt_collect_loop(), name="zt-audit")
    _background_tasks.append(zt_task)
    _background_tasks.append(ssh_task)
    logger.info("SSH collector started")
    # vpn_task = asyncio.create_task(vpn_collect_loop(), name="vpn-collector")

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("QUANSEC shutting down...")
    for task in _background_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await close_pool()
    logger.info("Shutdown complete")


app = FastAPI(
    title="QUANSEC — Post-Quantum Cryptography Platform",
    version="2.0.0",
    description="Real-time PQC monitoring for IPsec, TLS, SSH, and VPN",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:443"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount routers ─────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(api_keys_router)
app.include_router(ipsec_router)
app.include_router(ws_router)
app.include_router(policy_router)
app.include_router(attacks_router)
app.include_router(tls_router)
app.include_router(ssh_router)
app.include_router(ssh_ca_router)
app.include_router(scoring_router)
app.include_router(metrics_router)
app.include_router(siem_router)
app.include_router(alerts_router)
app.include_router(failmode_router)
app.include_router(ssh_policy_router)
app.include_router(zt_router)
# app.include_router(vpn_router)    # Phase 4


@app.get("/health")
async def health():
    pool = await get_pool()
    async with pool.acquire() as conn:
        db_ok = await conn.fetchval("SELECT 1") == 1
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "connected" if db_ok else "error",
        "collectors": [t.get_name() for t in _background_tasks if not t.done()],
    }


@app.get("/")
async def root():
    return {
        "service": "QUANSEC",
        "version": "2.0.0",
        "docs": "/docs",
        "protocols": ["ipsec", "tls", "ssh", "vpn (phase 4)"],
    }
