"""Securely create or explicitly reset the initial QUANSEC administrator."""

import argparse
import asyncio
import getpass
import os
import sys

from core.auth import hash_password
from core.database import close_pool, get_pool


def read_password() -> str:
    password = getpass.getpass("Admin password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm admin password: ")

    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    if password != confirmation:
        raise ValueError("Passwords do not match")
    if password == "CHANGE_ME":
        raise ValueError("Refusing insecure default password")

    return password


async def seed_admin(email: str, reset: bool) -> int:
    email = email.strip().lower()

    if "@" not in email:
        print("ERROR: provide a valid administrator email", file=sys.stderr)
        return 2

    pool = await get_pool()

    try:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT id FROM users WHERE lower(email) = lower($1)",
                email,
            )

            if existing and not reset:
                print(
                    "ERROR: administrator already exists; "
                    "use --reset to replace its password",
                    file=sys.stderr,
                )
                return 2

            try:
                password = read_password()
            except ValueError as error:
                print(f"ERROR: {error}", file=sys.stderr)
                return 2

            password_hash = hash_password(password)

            if existing:
                await conn.execute(
                    """
                    UPDATE users
                    SET password_hash = $1, role = 'admin', portal = 'main'
                    WHERE id = $2
                    """,
                    password_hash,
                    existing["id"],
                )
                action = "Reset"
            else:
                await conn.execute(
                    """
                    INSERT INTO users (email, password_hash, role, portal)
                    VALUES ($1, $2, 'admin', 'main')
                    """,
                    email,
                    password_hash,
                )
                action = "Created"

            print(f"{action} administrator: {email}")
            print("Password was not printed or logged.")
            return 0
    finally:
        await close_pool()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the initial QUANSEC administrator."
    )
    parser.add_argument(
        "--email",
        default=os.getenv("ADMIN_EMAIL", "admin@quansec.io"),
        help="Administrator email",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Explicitly reset an existing administrator password",
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    raise SystemExit(asyncio.run(seed_admin(arguments.email, arguments.reset)))
