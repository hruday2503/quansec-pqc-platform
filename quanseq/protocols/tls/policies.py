"""
protocols/tls/policies.py — the named TLS policies QUANSEQ can apply.

Three policies, and the differences between them are security-relevant rather
than cosmetic. Each one carries the claim it is allowed to support, so the API
and the UI can report the same wording instead of each inventing its own.

    strict-hybrid       TLS 1.3 + X25519MLKEM768 only. Fail-closed: a client
                        offering only classical groups is refused. The default.

    hybrid-preferred    Hybrid first, classical fallback. NOT downgrade-
                        resistant — an attacker who can strip the hybrid group
                        from the ClientHello gets a classical handshake and the
                        server accepts it. Requires explicit opt-in.

    classical-lab       No hybrid group at all. Exists so the portal can show a
                        measured comparison against classical TLS. Refused in
                        production mode, and never labelled quantum-safe.

`fail_closed` and `downgrade_resistant` are stored per policy rather than being
derived at render time, because the difference between "hybrid is available"
and "hybrid is required" is exactly the distinction this module exists to keep
visible. See is_fail_closed() in policy.py for the check applied to whatever is
actually running, which is what status reporting uses.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

HYBRID_GROUP = "X25519MLKEM768"

# TLS 1.3 suites. AES-256-GCM only for the strict policy: one suite means one
# thing to verify, and a probe offering anything else must be refused.
SUITE_AES256 = "TLS_AES_256_GCM_SHA384"
SUITE_TLS13_STANDARD = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"


@dataclass(frozen=True)
class TlsPolicyDefinition:
    """One named policy and the claims it is permitted to support."""

    name: str
    title: str
    summary: str

    protocols: str
    groups: str
    ciphersuites: str
    early_data: bool = False
    mtls: bool = False

    # A classical-only client is refused. True only when the group list
    # contains the hybrid group and nothing else.
    fail_closed: bool = False

    # Stripping the hybrid group from the ClientHello does NOT get a classical
    # handshake. Equivalent to fail_closed for these three policies, but kept
    # separate because they answer different questions and a future policy
    # could satisfy one without the other.
    downgrade_resistant: bool = False

    # May this policy be applied when QUANSEQ_ENV=production?
    production_allowed: bool = True

    # Requires the operator to pass acknowledge_risk=true on apply.
    requires_acknowledgement: bool = False

    # What may honestly be said about a connection under this policy. Never
    # composed in the browser, so there is one source of truth for the wording.
    key_establishment_claim: str = ""
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "title": self.title,
            "summary": self.summary,
            "protocols": self.protocols,
            "groups": self.groups,
            "ciphersuites": self.ciphersuites,
            "early_data": self.early_data,
            "mtls": self.mtls,
            "fail_closed": self.fail_closed,
            "downgrade_resistant": self.downgrade_resistant,
            "production_allowed": self.production_allowed,
            "requires_acknowledgement": self.requires_acknowledgement,
            "key_establishment_claim": self.key_establishment_claim,
            "warnings": list(self.warnings),
            # Authentication is reported separately from key establishment on
            # purpose. A hybrid exchange with an RSA or ECDSA certificate is
            # still classically authenticated, and no policy changes that.
            "authentication_note": (
                "Certificate authentication is classical X.509 and is not "
                "affected by this policy. Post-quantum authentication would "
                "require an ML-DSA certificate, verified independently."
            ),
        }


STRICT_HYBRID = TlsPolicyDefinition(
    name="strict-hybrid",
    title="Strict Hybrid",
    summary=(
        "TLS 1.3 with X25519MLKEM768 as the only offered group. A client that "
        "offers only classical groups is refused during the handshake."
    ),
    protocols="TLSv1.3",
    groups=HYBRID_GROUP,
    ciphersuites=SUITE_AES256,
    early_data=False,
    fail_closed=True,
    downgrade_resistant=True,
    production_allowed=True,
    key_establishment_claim=(
        "Hybrid post-quantum key establishment (X25519 + ML-KEM-768), enforced. "
        "Classical-only clients are refused."
    ),
)

HYBRID_PREFERRED = TlsPolicyDefinition(
    name="hybrid-preferred",
    title="Hybrid Preferred",
    summary=(
        "TLS 1.3 offering the hybrid group first with classical fallback. "
        "Compatible with clients that cannot do ML-KEM, at the cost of "
        "enforcement."
    ),
    protocols="TLSv1.3",
    groups=f"{HYBRID_GROUP}:x25519:secp256r1",
    ciphersuites=SUITE_TLS13_STANDARD,
    early_data=False,
    fail_closed=False,
    downgrade_resistant=False,
    production_allowed=True,
    requires_acknowledgement=True,
    key_establishment_claim=(
        "Hybrid post-quantum key establishment offered but NOT required. A "
        "session under this policy may have used classical X25519 or P-256; "
        "only the recorded negotiated group says which."
    ),
    warnings=[
        "NOT downgrade-resistant. An attacker who strips the hybrid group from "
        "the ClientHello gets a classical handshake, and this policy accepts it.",
        "Hybrid coverage under this policy is a measurement of what clients "
        "chose, not a guarantee of what they were required to do.",
    ],
)

CLASSICAL_LAB = TlsPolicyDefinition(
    name="classical-lab",
    title="Classical Lab",
    summary=(
        "TLS 1.3 with classical groups only. For controlled comparison against "
        "the hybrid policies. No post-quantum key establishment occurs."
    ),
    protocols="TLSv1.3",
    groups="x25519:secp256r1",
    ciphersuites=SUITE_TLS13_STANDARD,
    early_data=False,
    fail_closed=False,
    downgrade_resistant=False,
    production_allowed=False,
    requires_acknowledgement=True,
    key_establishment_claim=(
        "Classical key establishment only. Not quantum-safe. Recorded traffic "
        "under this policy is exposed to harvest-now-decrypt-later."
    ),
    warnings=[
        "No post-quantum protection whatsoever. This policy exists for "
        "measured comparison and is refused when QUANSEQ_ENV=production.",
    ],
)

POLICIES: Dict[str, TlsPolicyDefinition] = {
    p.name: p for p in (STRICT_HYBRID, HYBRID_PREFERRED, CLASSICAL_LAB)
}

DEFAULT_POLICY = STRICT_HYBRID.name


def get_policy(name: str) -> Optional[TlsPolicyDefinition]:
    """Look up a policy by name. Returns None for anything not on the list."""
    return POLICIES.get(name)


def policy_names() -> List[str]:
    return list(POLICIES.keys())


def validate_selection(name: str, *, production: bool,
                       acknowledged: bool) -> Optional[str]:
    """
    Whether this policy may be applied right now.

    Returns None when the selection is allowed, or a reason string when it is
    not. The caller turns that into a 400/403 — this function does not raise,
    so the same check can be used to grey out a button in the UI without
    triggering an exception path.
    """
    policy = get_policy(name)
    if policy is None:
        return f"Unknown policy '{name}'. Allowed: {', '.join(policy_names())}"

    if production and not policy.production_allowed:
        return (
            f"Policy '{name}' is not permitted in production mode. It disables "
            "post-quantum key establishment."
        )

    if policy.requires_acknowledgement and not acknowledged:
        reasons = " ".join(policy.warnings)
        return (
            f"Policy '{name}' weakens enforcement and requires explicit "
            f"acknowledgement (acknowledge_risk=true). {reasons}"
        )

    return None
