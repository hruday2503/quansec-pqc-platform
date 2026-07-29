"""
protocols/metrics/router.py — Prometheus / OpenTelemetry metrics export.

Exposes live platform state in Prometheus text exposition format at
/metrics, so any Prometheus/Grafana/OpenTelemetry collector can scrape it.
This is the standards-compliant telemetry export named in the proposal.

  GET /metrics    Prometheus text format (no auth — standard for scrapers,
                  or protect at the network layer)
"""

import logging

import asyncpg
from fastapi import APIRouter, Depends, Response

from core.database import get_db

logger = logging.getLogger("quansec.metrics")
router = APIRouter(tags=["Metrics"])


@router.get("/metrics")
async def prometheus_metrics(conn: asyncpg.Connection = Depends(get_db)):
    lines = []

    def metric(name, value, help_text, mtype="gauge", labels=""):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lbl = f"{{{labels}}}" if labels else ""
        lines.append(f"{name}{lbl} {value}")

    # IPsec metrics
    try:
        ip = await conn.fetch("SELECT pqc_enabled, state, bytes_in, bytes_out FROM ipsec_tunnels")
        ip_total = len(ip)
        ip_est = sum(1 for r in ip if r["state"] == "ESTABLISHED")
        ip_pqc = sum(1 for r in ip if r["pqc_enabled"])
        ip_bytes_in = sum(r["bytes_in"] or 0 for r in ip)
        ip_bytes_out = sum(r["bytes_out"] or 0 for r in ip)
        metric("quansec_ipsec_tunnels_total", ip_total, "Total IPsec tunnels")
        metric("quansec_ipsec_tunnels_established", ip_est, "Established IPsec tunnels")
        metric("quansec_ipsec_tunnels_pqc", ip_pqc, "PQC-enabled IPsec tunnels")
        metric("quansec_ipsec_pqc_coverage_percent", round((ip_pqc / ip_est * 100) if ip_est else 0, 1), "IPsec PQC coverage %")
        metric("quansec_ipsec_bytes_in_total", ip_bytes_in, "IPsec bytes received", "counter")
        metric("quansec_ipsec_bytes_out_total", ip_bytes_out, "IPsec bytes sent", "counter")
    except Exception as e:
        logger.debug(f"ipsec metrics: {e}")

    # SSH metrics
    try:
        sh = await conn.fetch("SELECT pqc_enabled, state, bytes_sent, bytes_received FROM ssh_connections")
        sh_total = len(sh)
        sh_active = sum(1 for r in sh if r["state"] == "ACTIVE")
        sh_pqc = sum(1 for r in sh if r["pqc_enabled"] and r["state"] == "ACTIVE")
        sh_bs = sum(r["bytes_sent"] or 0 for r in sh)
        sh_br = sum(r["bytes_received"] or 0 for r in sh)
        metric("quansec_ssh_sessions_total", sh_total, "Total SSH sessions seen")
        metric("quansec_ssh_sessions_active", sh_active, "Active SSH sessions")
        metric("quansec_ssh_sessions_pqc", sh_pqc, "PQC-enabled active SSH sessions")
        metric("quansec_ssh_pqc_coverage_percent", round((sh_pqc / sh_active * 100) if sh_active else 0, 1), "SSH PQC coverage %")
        metric("quansec_ssh_bytes_sent_total", sh_bs, "SSH bytes sent", "counter")
        metric("quansec_ssh_bytes_received_total", sh_br, "SSH bytes received", "counter")
    except Exception as e:
        logger.debug(f"ssh metrics: {e}")

    # Zero Trust metrics
    try:
        exists = await conn.fetchval("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='zt_audit')")
        if exists:
            zt = await conn.fetch("SELECT result FROM zt_audit")
            zt_acc = sum(1 for r in zt if r["result"] == "accepted")
            zt_rej = sum(1 for r in zt if r["result"] == "rejected")
            metric("quansec_zt_auth_accepted_total", zt_acc, "Zero Trust cert auths accepted", "counter")
            metric("quansec_zt_auth_rejected_total", zt_rej, "Zero Trust cert auths rejected", "counter")
    except Exception as e:
        logger.debug(f"zt metrics: {e}")

    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
