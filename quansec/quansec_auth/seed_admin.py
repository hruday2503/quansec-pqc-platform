import os
"""
seed_admin.py — create or reset the admin user with a proper password hash.

Run once after migrations:
    python3 seed_admin.py

Default credentials (CHANGE the password immediately in production):
    email:    admin@quansec.io
    password: <set via ADMIN_PASSWORD env>
"""

import asyncio
import sys

from core.database import get_pool, close_pool
from core.auth import hash_password

ADMIN_EMAIL = "admin@quansec.io"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE_ME")


async def main():
    pool = await get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM users WHERE email = $1", ADMIN_EMAIL)
        pw_hash = hash_password(ADMIN_PASSWORD)

        if existing:
            await conn.execute(
                "UPDATE users SET password_hash = $1, role = 'admin' WHERE email = $2",
                pw_hash, ADMIN_EMAIL,
            )
            print(f"Reset admin password for {ADMIN_EMAIL}")
        else:
            await conn.execute(
                "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin')",
                ADMIN_EMAIL, pw_hash,
            )
            print(f"Created admin user {ADMIN_EMAIL}")

        print(f"  email:    {ADMIN_EMAIL}")
        print(f"  password: {ADMIN_PASSWORD}")
        print("  CHANGE THIS PASSWORD in production!")

    await close_pool()


if __name__ == "__main__":
    asyncio.run(main())
