"""
core/scopes.py — the authorization vocabulary and how roles map onto it.

QUANSEC has two axes of access: which protocol module (tls, ssh, ipsec) and
what depth (read, admin). Scopes name a point on that grid; roles are the only
thing that decides which points a user gets.

**Scopes are derived, never supplied.** `scopes_for()` is the sole producer, and
its only inputs are the `role` and `portal` columns read from the database
during login. Nothing in the login request can influence the result — a client
that posts `scopes=["system:admin"]` is ignored, because that field is never
read. This is the whole reason the mapping lives in one small module instead of
being inlined at the call sites.

Adding a protocol module means adding its two scopes here and depending on
`require_scope(...)` in its router. It does not mean touching role handling.
"""

from typing import Dict, FrozenSet, Iterable, List, Sequence

# ── The vocabulary ───────────────────────────────────────────────────────────

TLS_READ = "tls:read"
# Run enforcement probes and validation tests. Deliberately BETWEEN read and
# admin: a probe spawns an OpenSSL client and writes evidence rows, which is
# more than reading, but it cannot change the running policy. A monitoring
# integration needs exactly this and must not be handed tls:admin to get it.
TLS_PROBE = "tls:probe"
TLS_ADMIN = "tls:admin"
SSH_READ = "ssh:read"
SSH_ADMIN = "ssh:admin"
IPSEC_READ = "ipsec:read"
IPSEC_ADMIN = "ipsec:admin"
SYSTEM_ADMIN = "system:admin"

ALL_SCOPES: FrozenSet[str] = frozenset({
    TLS_READ, TLS_PROBE, TLS_ADMIN,
    SSH_READ, SSH_ADMIN,
    IPSEC_READ, IPSEC_ADMIN,
    SYSTEM_ADMIN,
})

# `system:admin` is the platform-wide override: it satisfies any check without
# being enumerated everywhere. An admin scope also implies its read scope, so
# routes never have to ask for `{tls:read, tls:admin}` and risk one being
# forgotten.
IMPLIES: Dict[str, FrozenSet[str]] = {
    SYSTEM_ADMIN: ALL_SCOPES,
    # tls:admin implies probe as well as read — an administrator who can
    # replace the policy can certainly run a probe against it.
    TLS_ADMIN: frozenset({TLS_READ, TLS_PROBE}),
    # A prober can read what it produces. It cannot apply policy: tls:probe
    # deliberately does NOT imply tls:admin in either direction.
    TLS_PROBE: frozenset({TLS_READ}),
    SSH_ADMIN: frozenset({SSH_READ}),
    IPSEC_ADMIN: frozenset({IPSEC_READ}),
}

# Convenience sets for router dependencies.
TLS_READ_SCOPES = (TLS_READ, TLS_PROBE, TLS_ADMIN, SYSTEM_ADMIN)
TLS_PROBE_SCOPES = (TLS_PROBE, TLS_ADMIN, SYSTEM_ADMIN)
TLS_ADMIN_SCOPES = (TLS_ADMIN, SYSTEM_ADMIN)

# ── Role and portal mapping ──────────────────────────────────────────────────

# `users.role` is CHECK-constrained to admin | operator (migration 001).
#
# An operator gets read access to every module rather than only its own portal:
# the dashboard's cross-protocol views (scoring, metrics, readiness) read all
# three, and the pre-existing `require_user` dependency already allowed exactly
# this. Narrowing it here would revoke access that SSH and IPsec users have
# today, which is a behaviour change dressed up as a security fix.
_ROLE_SCOPES: Dict[str, FrozenSet[str]] = {
    "admin": frozenset({SYSTEM_ADMIN}),
    "operator": frozenset({TLS_READ, SSH_READ, IPSEC_READ}),
}

# A portal-scoped operator additionally administers its own protocol. This is
# what makes the TLS portal usable by a non-superuser: they can apply a policy
# and run probes on TLS, and stay read-only everywhere else.
_PORTAL_ADMIN_SCOPE: Dict[str, str] = {
    "tls": TLS_ADMIN,
    "ssh": SSH_ADMIN,
    "ipsec": IPSEC_ADMIN,
}


def scopes_for(role: str, portal: str | None = None) -> List[str]:
    """
    The scopes a user holds, from their database role and portal.

    The only source of authority in the system. An unknown role yields no
    scopes at all rather than a default set — a typo in the database must fail
    closed, not silently grant read access to everything.
    """
    granted = set(_ROLE_SCOPES.get((role or "").strip().lower(), frozenset()))

    if granted and portal:
        module_admin = _PORTAL_ADMIN_SCOPE.get(portal.strip().lower())
        # 'main' is the cross-protocol portal and grants no extra administration
        # on its own; it is not in the map, so it falls through to None here.
        if module_admin:
            granted.add(module_admin)

    return sorted(expand(granted))


def expand(scopes: Iterable[str]) -> FrozenSet[str]:
    """
    Close a scope set under implication.

    Expanding at issue time means the token carries every scope it grants, so
    verification is a plain set membership test and a route can never be
    bypassed by an implication rule the checker forgot to apply.
    """
    result = set()
    for scope in scopes:
        if scope not in ALL_SCOPES:
            continue
        result.add(scope)
        result |= IMPLIES.get(scope, frozenset())
    return frozenset(result)


def has_any(held: Sequence[str] | None, required: Sequence[str]) -> bool:
    """
    Whether `held` satisfies any of `required`.

    **Only the held side is expanded.** Expanding the required side too would
    invert the implication and grant access instead of restricting it: a route
    requiring `tls:admin` would expand that to {tls:admin, tls:read}, and a
    caller holding only `tls:read` would intersect non-emptily and pass. That is
    a privilege escalation, and it is what the
    `test_read_scope_does_not_imply_admin` test exists to catch.

    Held scopes are re-expanded rather than trusted as issued, so a token minted
    before an implication rule changed is evaluated under today's rules.
    """
    if not held:
        return False
    return bool(expand(held) & {scope for scope in required if scope in ALL_SCOPES})


def describe(scope: str) -> str:
    """Human-readable description, used by GET /api/auth/me and the docs."""
    return _DESCRIPTIONS.get(scope, scope)


_DESCRIPTIONS: Dict[str, str] = {
    TLS_READ: "Read TLS status, sessions, events and readiness",
    TLS_ADMIN: "Apply TLS policy, control the data plane, run probes, manage certificates",
    SSH_READ: "Read SSH status, connections and handshakes",
    SSH_ADMIN: "Apply SSH policy and issue certificates",
    IPSEC_READ: "Read IPsec status, tunnels and events",
    IPSEC_ADMIN: "Apply IPsec policy and run attack simulations",
    SYSTEM_ADMIN: "Full platform administration, including user management",
}
