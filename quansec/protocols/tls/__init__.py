"""
protocols/tls — the QUANSEC TLS protocol module.

TLS is an operational protocol module here, on the same footing as IPsec with
StrongSwan and SSH with OpenSSH:

    data plane      NGINX 1.27.5 linked against OpenSSL 3.5.7, fail-closed on
                    X25519MLKEM768, listening on 127.0.0.1:8443
    control plane   this package - renders the config, manages the process,
                    reads the logs, runs enforcement probes
    storage         PostgreSQL: tls_sessions, tls_events, tls_policy_state,
                    tls_probe_results, tls_certificates

Module layout:

    settings.py   validated configuration and runtime introspection
    service.py    NGINX config rendering, lifecycle, status evaluation
    policy.py     intended vs running policy, drift, apply
    collector.py  tails the real NGINX JSON access log into PostgreSQL
    probe.py      enforcement probes run with the runtime OpenSSL client
    certs.py      certificate facts; authentication reported separately
    router.py     the REST surface, scope-protected
    models.py     request and response schemas

The Python-`ssl` TLS 1.3 client this module grew out of now lives in
`legacy/tls13/`. It is retained as reusable client logic and as the historical
source (see its VENDOR.md), but it is not in the enforcement path: Python's
`ssl` module cannot select TLS 1.3 groups, which is exactly why the data plane
is NGINX.
"""

from .settings import TlsConfigurationError, TlsSettings, get_tls_settings

__all__ = ["TlsSettings", "TlsConfigurationError", "get_tls_settings"]
