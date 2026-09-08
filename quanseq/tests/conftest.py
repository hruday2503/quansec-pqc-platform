"""
tests/conftest.py — shared fixtures for the QUANSEQ backend test suite.

Database strategy: every test that touches PostgreSQL runs inside a transaction
that is rolled back at the end, so the suite leaves no rows behind and can be
run repeatedly against a live database.

The wrinkle is that `TestClient` runs the app in its own event loop while an
asyncpg connection is bound to the loop that created it. A single connection
cannot be shared between the two. So there are two paths:

  db_conn      an async fixture for tests that call persistence functions
               directly and then assert on the rows.
  api_client   a TestClient whose `get_db` dependency opens a fresh
               per-request transaction and rolls it back.

The consequence to remember: a write made through `api_client` is NOT visible
to a later request from the same client, because each request had its own
rolled-back transaction. Tests that need to observe persisted state use
`db_conn` and the module functions.
"""

import os
import pathlib
import sys
import uuid

import pytest

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


# ── Database ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def database_url() -> str:
    from core.config import settings
    return settings.DATABASE_URL


@pytest.fixture(scope="session")
def database_available(database_url) -> bool:
    """
    Whether PostgreSQL is reachable AND migrated.

    Applies the migrations as part of the check so a fresh database does not
    fail every test with a confusing "relation does not exist".
    """
    import asyncio

    import asyncpg

    async def _check() -> bool:
        try:
            conn = await asyncpg.connect(database_url, timeout=5)
        except Exception:
            return False
        try:
            for path in sorted((BACKEND_ROOT / "migrations").glob("*.sql")):
                await conn.execute(path.read_text())
            return True
        except Exception:
            return False
        finally:
            await conn.close()

    return asyncio.run(_check())


@pytest.fixture
async def db_conn(database_url, database_available):
    """A connection in a transaction that is rolled back when the test ends."""
    if not database_available:
        pytest.skip("PostgreSQL is not reachable at DATABASE_URL")

    import asyncpg

    conn = await asyncpg.connect(database_url)
    transaction = conn.transaction()
    await transaction.start()
    try:
        yield conn
    finally:
        await transaction.rollback()
        await conn.close()


def _rollback_db_dependency(database_url):
    """A `get_db` replacement giving each request its own rolled-back transaction."""
    import asyncpg

    async def _get_db():
        conn = await asyncpg.connect(database_url)
        transaction = conn.transaction()
        await transaction.start()
        try:
            yield conn
        finally:
            await transaction.rollback()
            await conn.close()

    return _get_db


# ── Application ──────────────────────────────────────────────────────────────

@pytest.fixture
def app_no_lifespan(database_url, database_available):
    """
    The FastAPI app with `get_db` overridden and the lifespan not run.

    The lifespan would start every background collector and hold a connection
    pool open for the whole session — irrelevant to these tests and a source of
    cross-test interference.
    """
    if not database_available:
        pytest.skip("PostgreSQL is not reachable at DATABASE_URL")

    from core.database import get_db
    from main import app

    app.dependency_overrides[get_db] = _rollback_db_dependency(database_url)
    try:
        yield app
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def api_client(app_no_lifespan):
    """
    A TestClient with real authentication left intact.

    Deliberately NOT stubbed: these tests are about the auth layer, so
    overriding it would test nothing. Callers log in for real.
    """
    from fastapi.testclient import TestClient

    with TestClient(app_no_lifespan) as client:
        yield client


@pytest.fixture
def committing_api_client(database_url, database_available):
    """
    A TestClient whose writes actually COMMIT.

    Needed for any flow spanning more than one request. `api_client` rolls each
    request back, so a refresh token created by a login request is gone before
    the refresh request looks for it — the login/refresh/logout sequence cannot
    be tested against it at all.

    The cost is real rows, so this fixture records the refresh tokens and audit
    events created during the test and deletes them afterwards. Users are
    cleaned up by `live_user`, and refresh_tokens cascades from users.id.
    """
    if not database_available:
        pytest.skip("PostgreSQL is not reachable at DATABASE_URL")

    import asyncio

    import asyncpg
    from fastapi.testclient import TestClient

    from main import app

    async def _high_water() -> tuple[int, int]:
        conn = await asyncpg.connect(database_url)
        try:
            return (
                await conn.fetchval("SELECT COALESCE(MAX(id), 0) FROM refresh_tokens"),
                await conn.fetchval("SELECT COALESCE(MAX(id), 0) FROM audit_events"),
            )
        finally:
            await conn.close()

    before_tokens, before_audit = asyncio.run(_high_water())

    # No get_db override: requests use the real pool and commit.
    with TestClient(app) as client:
        yield client

    async def _cleanup():
        conn = await asyncpg.connect(database_url)
        try:
            await conn.execute(
                "DELETE FROM refresh_tokens WHERE id > $1", before_tokens
            )
            await conn.execute("DELETE FROM audit_events WHERE id > $1", before_audit)
        finally:
            await conn.close()

    asyncio.run(_cleanup())


@pytest.fixture
def committing_login(committing_api_client):
    """`login`, but against the committing client."""
    def _login(user: dict, *, use_cookie: bool = False, portal: str | None = None):
        url = ("/api/auth/login-scoped?portal=" + portal if portal
               else "/api/auth/login")
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}use_cookie={'true' if use_cookie else 'false'}"
        return committing_api_client.post(
            url,
            data={"username": user["email"], "password": user["password"]},
        )

    return _login


# ── Users ────────────────────────────────────────────────────────────────────

# A password that satisfies the 12-character minimum on /register. Generated
# per-run rather than hardcoded so the suite never ships a usable credential.
TEST_PASSWORD = "test-" + uuid.uuid4().hex[:20]


@pytest.fixture
async def make_user(db_conn):
    """
    Factory creating a user inside the test transaction.

    Emails are UUID-suffixed so a partially-committed run cannot collide with
    the UNIQUE constraint on `users.email`.
    """
    from core.auth import hash_password

    async def _make(role: str = "operator", portal: str = "main",
                    password: str = TEST_PASSWORD):
        email = f"test-{uuid.uuid4().hex[:12]}@quanseq.test"
        row = await db_conn.fetchrow(
            """INSERT INTO users (email, password_hash, role, portal)
               VALUES ($1, $2, $3, $4)
               RETURNING id, email, role, portal""",
            email, hash_password(password), role, portal,
        )
        return {**dict(row), "password": password}

    return _make


@pytest.fixture
def live_user(database_url, database_available):
    """
    A user COMMITTED to the database, for tests that log in through the HTTP API.

    `api_client` rolls back each request's transaction, so a user created inside
    one is invisible to the login request. This fixture commits, and deletes the
    row afterwards.
    """
    if not database_available:
        pytest.skip("PostgreSQL is not reachable at DATABASE_URL")

    import asyncio

    import asyncpg

    from core.auth import hash_password

    created: list[int] = []

    async def _insert(role: str, portal: str, password: str):
        conn = await asyncpg.connect(database_url)
        try:
            email = f"live-{uuid.uuid4().hex[:12]}@quanseq.test"
            row = await conn.fetchrow(
                """INSERT INTO users (email, password_hash, role, portal)
                   VALUES ($1, $2, $3, $4)
                   RETURNING id, email, role, portal""",
                email, hash_password(password), role, portal,
            )
            created.append(row["id"])
            return {**dict(row), "password": password}
        finally:
            await conn.close()

    def _make(role: str = "operator", portal: str = "main",
              password: str = TEST_PASSWORD):
        return asyncio.run(_insert(role, portal, password))

    yield _make

    async def _cleanup():
        conn = await asyncpg.connect(database_url)
        try:
            # refresh_tokens cascades on users.id; audit_events sets NULL.
            await conn.execute("DELETE FROM users WHERE id = ANY($1::int[])", created)
        finally:
            await conn.close()

    if created:
        asyncio.run(_cleanup())


@pytest.fixture
def login(api_client):
    """
    Log in over HTTP and return the parsed token response.

    `use_cookie=false` by default so the refresh token comes back in the body,
    which is what a non-browser client does. Tests that exercise the cookie and
    CSRF path pass use_cookie=True.
    """
    def _login(user: dict, *, use_cookie: bool = False, portal: str | None = None):
        url = ("/api/auth/login-scoped?portal=" + portal if portal
               else "/api/auth/login")
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}use_cookie={'true' if use_cookie else 'false'}"
        return api_client.post(
            url,
            data={"username": user["email"], "password": user["password"]},
        )

    return _login


@pytest.fixture(autouse=True)
def clear_throttle():
    """
    Clear the login rate limiter between tests.

    Without this the suite's repeated failed-login tests trip the throttle and
    later tests fail with 429 for reasons unrelated to what they assert.
    """
    import asyncio

    async def _clear():
        try:
            from core.redis_client import get_redis_optional
            redis = await get_redis_optional()
            if redis is not None:
                keys = await redis.keys("quanseq:auth:throttle:*")
                if keys:
                    await redis.delete(*keys)
        except Exception:
            pass

    asyncio.run(_clear())
    yield
