#!/usr/bin/env python3
"""
scripts/generate_tls_certs.py — generate the TLS development PKI.

Creates a local root CA, a server certificate with a SAN, and a client
certificate for mTLS. Private keys are written mode 600.

This is the ONLY way to generate certificates in QUANSEQ. There is deliberately
no HTTP route for it: certificate generation rotates the trust anchor for the
whole TLS module, and an unauthenticated (or even authenticated) endpoint that
can do that is a privilege-escalation surface, not a feature.

Usage:
    python scripts/generate_tls_certs.py
    python scripts/generate_tls_certs.py --cert-dir ~/quanseq-certs
    python scripts/generate_tls_certs.py --extra-ip 192.168.1.50   # two-machine
    python scripts/generate_tls_certs.py --force                   # overwrite

The default directory comes from QUANSEQ_TLS_CERT_DIR, which should point
outside the repository.
"""

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import settings                       # noqa: E402
from protocols.tls.tls13 import CertManager            # noqa: E402
from protocols.tls.tls13.exceptions import CertGenerationError  # noqa: E402

logger = logging.getLogger("quanseq.tls.certs")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the QUANSEQ TLS development PKI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The generated CA private key can mint certificates trusted by the\n"
            "TLS service. Keep the directory outside the repository and readable\n"
            "only by the service user. This is development material, not\n"
            "production PKI."
        ),
    )
    parser.add_argument(
        "--cert-dir", default=settings.TLS_CERT_DIR,
        help="output directory (default: QUANSEQ_TLS_CERT_DIR = %(default)s)",
    )
    parser.add_argument(
        "--extra-ip", action="append", default=[], metavar="IP",
        help="extra IP for the server SAN; repeatable. Use the peer machine's "
             "address to make one PKI work in two-machine mode.",
    )
    parser.add_argument(
        "--extra-dns", action="append", default=[], metavar="NAME",
        help="extra DNS name for the server SAN; repeatable",
    )
    parser.add_argument("--days", type=int, default=825, help="validity (default: %(default)s)")
    parser.add_argument("--force", action="store_true",
                        help="regenerate even if certificates already exist")
    parser.add_argument("--openssl", default=settings.TLS_OPENSSL_BIN,
                        help="openssl binary (default: %(default)s)")
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")
    args = parse_args()

    cert_dir = os.path.expanduser(args.cert_dir)
    manager = CertManager(cert_dir=cert_dir, days=args.days, openssl_bin=args.openssl)

    if manager.certs_exist() and not args.force:
        print(f"Certificates already present in {cert_dir}. Nothing to do.")
        print("Re-run with --force to regenerate. That invalidates every existing")
        print("certificate signed by the current CA.")
        return 0

    try:
        manager.generate_all(extra_ips=args.extra_ip, extra_dns=args.extra_dns)
    except CertGenerationError as exc:
        print(f"Certificate generation failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(f"Development PKI written to {cert_dir}")
    for label, path in [
        ("CA certificate", manager.ca_cert),
        ("CA private key", manager.ca_key),
        ("Server certificate", manager.server_cert),
        ("Server private key", manager.server_key),
        ("Client certificate", manager.client_cert),
        ("Client private key", manager.client_key),
    ]:
        mode = oct(os.stat(path).st_mode & 0o777)
        print(f"  {label:20s} {path}  ({mode})")

    if not cert_dir.rstrip("/").startswith(os.path.expanduser("~")):
        print()
        print("NOTE: this directory is not under your home directory. Confirm it is")
        print("      outside the git repository before continuing.")

    print()
    print("Point the backend at it with:")
    print(f"  QUANSEQ_TLS_CERT_DIR={cert_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
