"""
tests/conftest.py — shared fixtures for the QUANSEC test suite.

Every TLS test generates its own throwaway PKI into a temp directory and binds
an ephemeral port. No fixture reads or writes QUANSEC_TLS_CERT_DIR, so running
the suite can never touch or overwrite a real development PKI.
"""

import os
import pathlib
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocols.tls.tls13 import CertManager, TLSConfig  # noqa: E402

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent


def free_port() -> int:
    """An ephemeral port that was free a moment ago."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def pki(tmp_path_factory) -> CertManager:
    """
    A development PKI generated once per test session.

    Session-scoped because generating a 4096-bit CA plus two leaf certificates
    costs a few seconds and nothing in the suite mutates it.
    """
    cert_dir = tmp_path_factory.mktemp("quansec-test-pki")
    manager = CertManager(cert_dir=str(cert_dir))
    manager.generate_all()
    return manager


@pytest.fixture
def tls_config(pki):
    """
    Factory for a TLSConfig wired to the test PKI on a fresh ephemeral port.

        cfg = tls_config()                    # server and client agree
        cfg = tls_config(mtls=True)
        cfg = tls_config(port=other.port)     # point a client at an existing server
    """

    def _make(**overrides) -> TLSConfig:
        params = dict(
            host="127.0.0.1",
            port=overrides.pop("port", None) or free_port(),
            cert_dir=pki.cert_dir,
            ca_cert=pki.ca_cert,
            server_cert=pki.server_cert,
            server_key=pki.server_key,
            client_cert=pki.client_cert,
            client_key=pki.client_key,
            server_hostname="localhost",
            # The suite must run on stock OpenSSL 3.0.13, which has no hybrid
            # group. Requiring it would make every test fail to build a context.
            require_hybrid_tls=False,
            timeout=5,
            handshake_timeout=2.0,
        )
        params.update(overrides)
        return TLSConfig(**params)

    return _make


class _RecordingRelay:
    """
    A TCP tap that forwards bytes between a client and a server, recording
    everything it sees. Used to prove that payloads are encrypted on the wire.
    """

    def __init__(self, target_host: str, target_port: int):
        self.target = (target_host, target_port)
        self._captured = bytearray()
        self._lock = threading.Lock()
        self._running = True

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(5)
        self._listener.settimeout(0.5)
        self.port = self._listener.getsockname()[1]

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def captured(self) -> bytes:
        with self._lock:
            return bytes(self._captured)

    def close(self) -> None:
        self._running = False
        self._thread.join(timeout=3)
        try:
            self._listener.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._proxy, args=(client,), daemon=True).start()

    def _proxy(self, client: socket.socket) -> None:
        try:
            upstream = socket.create_connection(self.target, timeout=5)
        except OSError:
            client.close()
            return

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    chunk = src.recv(4096)
                    if not chunk:
                        break
                    with self._lock:
                        self._captured.extend(chunk)
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                for sock in (src, dst):
                    try:
                        sock.close()
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


@pytest.fixture
def recording_relay():
    """Factory for a _RecordingRelay, torn down at the end of the test."""
    relays = []

    def _make(host: str, port: int) -> _RecordingRelay:
        relay = _RecordingRelay(host, port)
        relays.append(relay)
        return relay

    yield _make

    for relay in relays:
        relay.close()


@pytest.fixture
def running_server(tls_config):
    """
    Start a TLSServer, yield (server, config), and guarantee it is stopped.

        server, cfg = running_server()
        server, cfg = running_server(mtls=True, handler=my_handler)
    """
    from protocols.tls.tls13 import TLSServer

    started = []

    def _start(handler=None, **overrides):
        config = tls_config(**overrides)
        server = TLSServer(config)
        if handler is not None:
            server.set_handler(handler)
        server.start_background()
        started.append(server)
        return server, config

    yield _start

    for server in started:
        server.stop()


# ── Database fixtures ────────────────────────────────────────────────────────
#
# Tests run against the configured PostgreSQL inside a transaction that is
# always rolled back, so the suite can exercise real SQL without leaving rows
# behind. If no database is reachable, the DB-backed tests skip rather than
# fail — the transport and hybrid suites do not need one.

@pytest.fixture(scope="session")
def database_url() -> str:
    from core.config import settings
    return settings.DATABASE_URL


@pytest.fixture(scope="session")
def database_available(database_url) -> bool:
    import asyncio

    import asyncpg

    async def _check() -> bool:
        try:
            conn = await asyncpg.connect(database_url, timeout=5)
        except Exception:
            return False
        try:
            await conn.execute(
                (BACKEND_ROOT / "migrations" / "007_tls.sql").read_text()
            )
            return True
        except Exception:
            return False
        finally:
            await conn.close()

    return asyncio.run(_check())


@pytest.fixture
async def db_conn(database_url, database_available):
    """
    A connection inside a transaction that is rolled back when the test ends.

    For async tests only. An asyncpg connection is bound to the event loop that
    created it, so this must not be handed to the TestClient — see db_override.
    """
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
    """
    A get_db replacement that gives each request its own rolled-back transaction.

    Per-request rather than per-test because TestClient runs the app in its own
    event loop, and an asyncpg connection cannot be shared across loops. The
    trade-off is that writes are not visible to a later request, so tests that
    need to observe persisted rows use the async db_conn fixture and call the
    persistence functions directly.
    """
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


@pytest.fixture
def api_client(database_url, database_available):
    """
    A TestClient with the database and authentication dependencies overridden.

    Auth is stubbed because these tests are about TLS behaviour. The auth
    dependencies themselves are exercised by test_all_tls_routes_require_
    authentication, which deliberately does not use this fixture.
    """
    if not database_available:
        pytest.skip("PostgreSQL is not reachable at DATABASE_URL")

    with unauthenticated_client(database_url) as client:
        admin = {"id": 1, "email": "admin@quansec.io", "role": "admin"}
        _override_auth(client.app, user=admin, admin=admin)
        yield client


@pytest.fixture
def raw_api_client(database_url, database_available):
    """A TestClient with the database overridden but authentication left intact."""
    if not database_available:
        pytest.skip("PostgreSQL is not reachable at DATABASE_URL")

    with unauthenticated_client(database_url) as client:
        yield client


class unauthenticated_client:
    """
    Context manager yielding a TestClient with only get_db overridden.

    The app is NOT entered as a context manager: doing so runs the lifespan,
    which opens a connection pool and starts every collector in the platform.
    These tests exercise routes, so the lifespan is deliberately skipped.
    """

    def __init__(self, database_url: str):
        self.database_url = database_url
        self.client = None

    def __enter__(self):
        from fastapi.testclient import TestClient

        import main
        from core.database import get_db

        main.app.dependency_overrides[get_db] = _rollback_db_dependency(self.database_url)
        self.client = TestClient(main.app, raise_server_exceptions=False)
        return self.client

    def __exit__(self, *exc_info):
        import main

        main.app.dependency_overrides.clear()
        return False


def _override_auth(app, *, user: dict, admin) -> None:
    """Replace the auth dependencies. `admin` may be a dict or a raising callable."""
    from core.auth import require_admin, require_user

    app.dependency_overrides[require_user] = lambda: user
    if callable(admin):
        app.dependency_overrides[require_admin] = admin
    else:
        app.dependency_overrides[require_admin] = lambda: admin
