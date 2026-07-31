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

    # TLS metrics
    #
    # quansec_tls_handshakes_pqc counts only observations backed by verified
    # hybrid evidence. On a runtime without X25519MLKEM768 it is legitimately
    # zero, and a dashboard showing zero reports a fact rather than missing data.
    try:
        tls = await conn.fetch(
            "SELECT outcome, pqc_enabled, tls_version, handshake_ms FROM tls_sessions"
        )
        tls_total = len(tls)
        tls_ok = sum(1 for r in tls if r["outcome"] == "success")
        tls_pqc = sum(1 for r in tls if r["pqc_enabled"])
        tls_13 = sum(1 for r in tls if r["tls_version"] == "TLSv1.3")
        latencies = sorted(r["handshake_ms"] for r in tls if r["handshake_ms"] is not None)

        metric("quansec_tls_handshakes_total", tls_total, "TLS handshake observations", "counter")
        metric("quansec_tls_handshakes_successful", tls_ok, "Successful TLS handshakes", "counter")
        metric("quansec_tls_handshakes_failed", tls_total - tls_ok, "Failed TLS handshakes", "counter")
        metric("quansec_tls_handshakes_pqc", tls_pqc,
               "TLS handshakes with verified hybrid PQC evidence", "counter")
        metric("quansec_tls_pqc_coverage_percent",
               round((tls_pqc / tls_ok * 100) if tls_ok else 0, 1), "TLS PQC coverage %")
        metric("quansec_tls13_handshakes", tls_13, "Handshakes negotiating TLS 1.3", "counter")
        if latencies:
            metric("quansec_tls_handshake_duration_ms",
                   round(latencies[len(latencies) // 2], 2),
                   "Median TLS handshake duration in milliseconds")

        evidence = await conn.fetchval(
            "SELECT COUNT(*) FROM tls_hybrid_evidence WHERE verified = TRUE"
        )
        metric("quansec_tls_hybrid_verifications_total", evidence or 0,
               "Successful out-of-band hybrid group verifications", "counter")
        # Exported as a constant 0 so an operator can alert on it ever flipping,
        # rather than having to read a document to learn enforcement is absent.
        metric("quansec_tls_hybrid_enforced", 0,
               "1 if hybrid key exchange is enforced; always 0 while Python ssl "
               "cannot select TLS 1.3 groups")
    except Exception as e:
        logger.debug(f"tls metrics: {e}")

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
