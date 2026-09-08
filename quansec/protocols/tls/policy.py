"""
protocols/tls/policy.py — the enforced TLS policy, and whether NGINX is running it.

QUANSEC's claim about TLS rests on one question: **is the policy on disk the
policy that is running, and is that policy fail-closed?** This module answers it.

Three distinct things are kept apart on purpose, because collapsing them is how
a dashboard ends up asserting protection it does not have:

  intended    what the environment says the policy should be (settings)
  rendered    what was actually written to nginx.conf and hashed
  running     what the live NGINX process loaded

Drift between them is reported, never smoothed over. A hand-edited nginx.conf,
or a policy applied but never reloaded, shows up as drift rather than silently
being reported as the intended policy.

`is_fail_closed()` is the load-bearing predicate. It returns True only when the
group list contains exactly the hybrid group — one classical fallback entry and
the endpoint is no longer fail-closed, whatever the rest of the status says.
"""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import asyncpg

from .service import NginxTlsService, config_digest, render_config
from .settings import TlsSettings, get_tls_settings

logger = logging.getLogger("quansec.tls.policy")

POLICY_NAME = "quansec-pqc-tls"


@dataclass
class PolicyView:
    """One policy, from one source, plus what it implies."""

    source: str                      # intended | rendered | running
    protocols: str
    groups: str
    ciphersuites: str
    mtls: bool
    early_data: bool
    listen: Optional[str] = None
    config_sha256: Optional[str] = None

    # Derived. Never set by a caller.
    tls13_only: bool = False
    hybrid_group_only: bool = False
    fail_closed: bool = False
    fallback_groups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_groups(groups: str) -> List[str]:
    """Split an ssl_conf_command Groups value into names."""
    return [g for g in re.split(r"[:,\s]+", groups or "") if g]


def is_fail_closed(groups: str, hybrid_group: str) -> tuple[bool, List[str]]:
    """
    Whether the group list admits only the hybrid group.

    Returns (fail_closed, fallback_groups). Any group other than the hybrid one
    is a fallback a client can negotiate instead, which means a classical key
    exchange is still reachable and "enforced" would be a false claim.
    """
    names = parse_groups(groups)
    if not names:
        # An empty list is not enforcement — it is no policy at all, and OpenSSL
        # would fall back to its own defaults.
        return False, []
    fallbacks = [n for n in names if n.lower() != hybrid_group.lower()]
    return (not fallbacks and len(names) == 1), fallbacks


def _evaluate(view: PolicyView, hybrid_group: str) -> PolicyView:
    """Fill in the derived fields on a view."""
    view.tls13_only = view.protocols.strip() == "TLSv1.3"
    fail_closed, fallbacks = is_fail_closed(view.groups, hybrid_group)
    view.hybrid_group_only = fail_closed
    view.fallback_groups = fallbacks
    # Fail-closed needs BOTH: TLS 1.2 carries key exchange in the cipher suite
    # and cannot negotiate a hybrid group at all, so allowing 1.2 reopens the
    # classical path no matter how the group list is written.
    view.fail_closed = fail_closed and view.tls13_only
    return view


def intended_policy(settings: Optional[TlsSettings] = None) -> PolicyView:
    """The policy the environment asks for. Nothing is running yet."""
    s = settings or get_tls_settings()
    return _evaluate(
        PolicyView(
            source="intended",
            protocols=s.protocols,
            groups=s.groups,
            ciphersuites=s.ciphersuites,
            mtls=s.mtls,
            early_data=s.early_data,
            listen=f"{s.host}:{s.port}",
            config_sha256=config_digest(render_config(s)),
        ),
        s.hybrid_group,
    )


def running_policy(service: Optional[NginxTlsService] = None) -> Optional[PolicyView]:
    """
    The policy parsed back out of the nginx.conf on disk.

    Returns None when there is no config file — the data plane has never been
    started, which is a different state from "running something unexpected".

    Reads the file rather than trusting settings, so a config edited by hand
    after the last apply is reported as what it is.
    """
    svc = service or NginxTlsService()
    parsed = svc._running_policy()          # noqa: SLF001 - same package
    if not parsed:
        return None

    return _evaluate(
        PolicyView(
            source="running",
            protocols=parsed.get("protocols", ""),
            groups=parsed.get("groups", ""),
            ciphersuites=parsed.get("ciphersuites", ""),
            mtls=parsed.get("mtls", False),
            early_data=parsed.get("early_data", False),
            listen=parsed.get("listen"),
            config_sha256=svc.current_config_digest(),
        ),
        svc.settings.hybrid_group,
    )


def compare(intended: PolicyView, running: Optional[PolicyView]) -> Dict[str, Any]:
    """
    Drift between intended and running policy.

    `config_sha256` alone would say "something differs"; naming the fields says
    what, which is what an operator needs before deciding whether to reload.
    """
    if running is None:
        return {
            "in_sync": False,
            "reason": "no_config",
            "detail": "No nginx.conf has been rendered yet. "
                      "Run scripts/start-pqc-tls.sh or POST /api/tls/policy/apply.",
            "differences": [],
        }

    differences = []
    for field_name in ("protocols", "groups", "ciphersuites", "mtls", "early_data"):
        want = getattr(intended, field_name)
        have = getattr(running, field_name)
        if str(want).strip() != str(have).strip():
            differences.append({"field": field_name, "intended": want, "running": have})

    return {
        "in_sync": not differences,
        "reason": "match" if not differences else "drift",
        "detail": ("The running configuration matches the intended policy."
                   if not differences else
                   "The running nginx.conf differs from the intended policy. "
                   "It may have been edited by hand, or a policy change was "
                   "applied without a reload."),
        "differences": differences,
        "intended_sha256": intended.config_sha256,
        "running_sha256": running.config_sha256,
    }


# ── Persistence ──────────────────────────────────────────────────────────────

async def record_policy_state(conn: asyncpg.Connection, view: PolicyView, *,
                              validated: bool, applied_by: Optional[str],
                              config_path: str) -> int:
    """
    Record an applied policy in `tls_policy_state`.

    The previous row is deactivated first, so exactly one row is `active` and
    the table doubles as an apply history.
    """
    await conn.execute(
        "UPDATE tls_policy_state SET active = FALSE WHERE policy_name = $1 AND active",
        POLICY_NAME,
    )
    return await conn.fetchval(
        """INSERT INTO tls_policy_state (
               policy_name, ssl_protocols, groups, ciphersuites, mtls_enabled,
               early_data, listen_addr, config_path, config_sha256, validated,
               active, applied_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,$11)
           RETURNING id""",
        POLICY_NAME, view.protocols, view.groups, view.ciphersuites, view.mtls,
        view.early_data, view.listen or "", config_path, view.config_sha256,
        validated, applied_by,
    )


async def active_policy_state(conn: asyncpg.Connection) -> Optional[Dict[str, Any]]:
    """The most recently applied policy row, or None."""
    row = await conn.fetchrow(
        """SELECT * FROM tls_policy_state
           WHERE policy_name = $1 AND active
           ORDER BY applied_at DESC LIMIT 1""",
        POLICY_NAME,
    )
    return dict(row) if row else None


async def record_event(conn: asyncpg.Connection, event_type: str, summary: str, *,
                       severity: str = "info",
                       detail: Optional[Dict[str, Any]] = None) -> None:
    """Append to `tls_events`. Mirrors collector.record_event."""
    await conn.execute(
        """INSERT INTO tls_events (event_type, severity, summary, detail)
           VALUES ($1, $2, $3, $4::jsonb)""",
        event_type, severity, summary, json.dumps(detail or {}, default=str),
    )


async def apply_policy(conn: asyncpg.Connection, *, applied_by: str,
                       settings: Optional[TlsSettings] = None,
                       reload: bool = True) -> Dict[str, Any]:
    """
    Render the intended policy, validate it with `nginx -t`, and reload.

    Validation before reload is not optional: applying a config NGINX rejects
    would otherwise take the data plane down on the next restart, and the
    failure would surface long after the change that caused it.

    A rejected config is recorded with `validated = FALSE` and NOT activated, so
    the audit trail shows the attempt without the status page ever treating it
    as the running policy.
    """
    s = settings or get_tls_settings()
    service = NginxTlsService(s)
    view = intended_policy(s)

    if not view.fail_closed:
        # Refusing here rather than warning: the whole point of this module is
        # that a policy which permits classical key exchange must never be
        # applied and then reported as enforcement.
        await record_event(
            conn, "config_rejected",
            "Refused to apply a policy that is not fail-closed",
            severity="critical",
            detail={"groups": view.groups, "protocols": view.protocols,
                    "fallback_groups": view.fallback_groups,
                    "applied_by": applied_by},
        )
        return {
            "applied": False,
            "reason": "not_fail_closed",
            "detail": (
                f"QUANSEC_TLS_GROUPS={view.groups!r} with "
                f"QUANSEC_TLS_PROTOCOLS={view.protocols!r} would allow a classical "
                "key exchange. Applying it would make every enforcement claim on "
                "the dashboard false."
            ),
            "fallback_groups": view.fallback_groups,
            "policy": view.to_dict(),
        }

    service.write_config()
    ok, output = service.validate_config()

    state_id = await record_policy_state(
        conn, view, validated=ok, applied_by=applied_by,
        config_path=s.nginx_conf,
    )

    if not ok:
        await conn.execute(
            "UPDATE tls_policy_state SET active = FALSE WHERE id = $1", state_id
        )
        await record_event(
            conn, "config_rejected", "nginx -t rejected the rendered configuration",
            severity="critical",
            detail={"output": output[:2000], "applied_by": applied_by},
        )
        return {"applied": False, "reason": "invalid_config", "detail": output,
                "policy": view.to_dict()}

    await record_event(
        conn, "config_validated", "nginx -t accepted the rendered configuration",
        detail={"config_sha256": view.config_sha256, "applied_by": applied_by},
    )

    reloaded = False
    reload_detail = "not requested"
    if reload:
        if service.is_running():
            reloaded, reload_detail = service.reload()
            await record_event(
                conn, "service_reload" if reloaded else "config_rejected",
                "NGINX reloaded with the new policy" if reloaded
                else f"NGINX reload failed: {reload_detail}",
                severity="info" if reloaded else "critical",
                detail={"applied_by": applied_by, "output": reload_detail[:1000]},
            )
        else:
            # Not an error: a config written while the service is down is picked
            # up on the next start. Saying so beats implying it took effect now.
            reload_detail = ("NGINX is not running; the configuration will take "
                             "effect on the next start")

    await record_event(
        conn, "policy_applied", "TLS policy applied",
        detail={"groups": view.groups, "protocols": view.protocols,
                "ciphersuites": view.ciphersuites, "mtls": view.mtls,
                "config_sha256": view.config_sha256, "reloaded": reloaded,
                "applied_by": applied_by},
    )

    return {
        "applied": True,
        "validated": True,
        "reloaded": reloaded,
        "detail": reload_detail,
        "policy_state_id": state_id,
        "policy": view.to_dict(),
        "nginx_output": output,
    }
