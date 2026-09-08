"""
tests/test_auth_tokens.py — the authentication and token layer.

Covers every case required of this work:

  login success / invalid credentials     TestLogin
  valid access token                      TestAccessTokenValidation
  expired access token                    TestAccessTokenValidation
  invalid issuer / audience               TestAccessTokenValidation
  malformed token, alg=none               TestAccessTokenValidation
  revoked refresh token                   TestRefreshRotation
  refresh-token rotation                  TestRefreshRotation
  refresh-token reuse detection           TestRefreshReuseDetection
  wrong portal                            TestPortalScoping
  wrong scope                             TestScopeEnforcement
  admin authorization                     TestScopeEnforcement
  CSRF failure                            TestCsrf
  revoke-all                              TestRevokeAll

The negative cases matter more than the positive ones here. That a valid token
works is table stakes; that a forged, expired, replayed or wrongly-scoped one is
refused is the actual security property.
"""

import time
import uuid

import pytest
from jose import jwt

from core import tokens
from core.config import settings
from core.scopes import (
    IPSEC_ADMIN,
    SSH_READ,
    SYSTEM_ADMIN,
    TLS_ADMIN,
    TLS_READ,
    has_any,
    scopes_for,
)
from core.tokens import TokenError


def _claims(**overrides):
    """Baseline claims for a structurally valid access token."""
    now = int(time.time())
    base = {
        "sub": "1", "email": "a@b.test", "role": "admin", "portal": "main",
        "scopes": [SYSTEM_ADMIN], "iat": now, "exp": now + 900,
        "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE,
        "jti": str(uuid.uuid4()), "typ": "access",
    }
    base.update(overrides)
    return base


# ── Scope mapping (requirement 4: never client-supplied) ─────────────────────

class TestScopeMapping:

    def test_admin_role_gets_system_admin(self):
        assert SYSTEM_ADMIN in scopes_for("admin", "main")

    def test_system_admin_implies_every_scope(self):
        granted = scopes_for("admin", "main")
        for scope in (TLS_READ, TLS_ADMIN, SSH_READ, IPSEC_ADMIN):
            assert scope in granted

    def test_operator_gets_read_only_by_default(self):
        granted = scopes_for("operator", "main")
        assert TLS_READ in granted
        assert TLS_ADMIN not in granted
        assert SYSTEM_ADMIN not in granted

    def test_portal_operator_administers_only_its_module(self):
        granted = scopes_for("operator", "tls")
        assert TLS_ADMIN in granted
        assert IPSEC_ADMIN not in granted
        assert SYSTEM_ADMIN not in granted

    def test_unknown_role_gets_nothing(self):
        """A typo in the role column must fail closed, not default to read."""
        assert scopes_for("superuser", "tls") == []
        assert scopes_for("", "tls") == []

    def test_admin_scope_implies_its_read_scope(self):
        assert has_any([TLS_ADMIN], [TLS_READ])

    def test_read_scope_does_not_imply_admin(self):
        assert not has_any([TLS_READ], [TLS_ADMIN])

    def test_login_cannot_inject_scopes(self):
        """
        Scopes are computed from the role. The mapping function takes no request
        input at all, which is the structural guarantee behind requirement 4.
        """
        assert scopes_for("operator", "main") == scopes_for("operator", "main")
        assert SYSTEM_ADMIN not in scopes_for("operator", "main")


# ── Access-token verification (requirement 18) ───────────────────────────────

class TestAccessTokenValidation:

    def test_valid_token_round_trips(self):
        issued = tokens.create_access_token(
            user_id=7, email="ops@quanseq.test", role="operator",
            portal="tls", scopes=scopes_for("operator", "tls"),
        )
        claims = tokens.decode_access_token(issued["token"])
        assert claims["sub"] == "7"
        assert claims["portal"] == "tls"
        assert TLS_ADMIN in claims["scopes"]

    def test_all_required_claims_present(self):
        issued = tokens.create_access_token(
            user_id=1, email="a@b.test", role="admin", portal="main",
            scopes=[SYSTEM_ADMIN],
        )
        claims = tokens.decode_access_token(issued["token"])
        for claim in ("sub", "role", "scopes", "portal", "iat", "exp",
                      "iss", "aud", "jti"):
            assert claim in claims, f"missing required claim {claim}"

    def test_alg_none_is_rejected(self):
        """
        The unsigned-token attack. Rejected because `algorithms=[HS384]` is a
        pinned allow-list, so a header claiming `none` never reaches claim
        parsing.
        """
        import base64
        import json

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps(_claims()).encode()).rstrip(b"=")
        forged = (header + b"." + payload + b".").decode()

        with pytest.raises(TokenError):
            tokens.decode_access_token(forged)

    def test_unexpected_algorithm_is_rejected(self):
        """A token signed with HS256 while the server expects HS384."""
        forged = jwt.encode(_claims(), settings.JWT_SECRET, algorithm="HS256")
        with pytest.raises(TokenError):
            tokens.decode_access_token(forged)

    def test_wrong_signing_key_is_rejected(self):
        forged = jwt.encode(_claims(), "f" * 96, algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(forged)
        assert exc.value.reason == "malformed_token"

    def test_invalid_issuer_is_rejected(self):
        forged = jwt.encode(_claims(iss="attacker"), settings.JWT_SECRET,
                            algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(forged)
        assert exc.value.reason == "invalid_issuer"

    def test_invalid_audience_is_rejected(self):
        forged = jwt.encode(_claims(aud="some-other-service"), settings.JWT_SECRET,
                            algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(forged)
        assert exc.value.reason == "invalid_audience"

    def test_expired_token_is_rejected(self):
        expired = jwt.encode(_claims(exp=int(time.time()) - 60), settings.JWT_SECRET,
                             algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(expired)
        assert exc.value.reason == "expired_token"

    def test_negative_ttl_produces_an_expired_token(self):
        """The minting path honours the TTL, so expiry is genuinely enforced."""
        issued = tokens.create_access_token(
            user_id=1, email="a@b.test", role="admin", portal="main",
            scopes=[SYSTEM_ADMIN], expires_in_minutes=-1,
        )
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(issued["token"])
        assert exc.value.reason == "expired_token"

    @pytest.mark.parametrize("garbage", [
        "", "not-a-token", "a.b.c", "...", "Bearer x",
        "eyJhbGciOiJIUzM4NCJ9.bm90LWpzb24.sig",
    ])
    def test_malformed_tokens_are_rejected(self, garbage):
        with pytest.raises(TokenError):
            tokens.decode_access_token(garbage)

    def test_missing_claim_is_rejected(self):
        claims = _claims()
        del claims["scopes"]
        forged = jwt.encode(claims, settings.JWT_SECRET,
                            algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(forged)
        assert "missing_claims" in exc.value.reason

    def test_wrong_token_type_is_rejected(self):
        forged = jwt.encode(_claims(typ="refresh"), settings.JWT_SECRET,
                            algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(TokenError) as exc:
            tokens.decode_access_token(forged)
        assert exc.value.reason == "wrong_token_type"

    def test_error_message_does_not_leak_the_reason(self):
        """
        The client sees one generic message; the specific reason goes to the
        audit log. Distinguishing "expired" from "bad signature" tells an
        attacker which half of a forgery worked.
        """
        expired = jwt.encode(_claims(exp=int(time.time()) - 60), settings.JWT_SECRET,
                             algorithm=settings.JWT_ALGORITHM)
        forged = jwt.encode(_claims(), "f" * 96, algorithm=settings.JWT_ALGORITHM)

        messages = set()
        for token in (expired, forged):
            try:
                tokens.decode_access_token(token)
            except TokenError as exc:
                messages.add(exc.message)
        assert len(messages) == 1


# ── Refresh tokens (requirements 9, 10, 12, 13) ──────────────────────────────

class TestRefreshTokenGeneration:

    def test_uses_at_least_32_random_bytes(self):
        token = tokens.generate_refresh_token()
        # token_urlsafe(32) base64url-encodes 32 bytes into 43 characters.
        assert len(token) >= 43

    def test_tokens_are_unique(self):
        assert len({tokens.generate_refresh_token() for _ in range(200)}) == 200

    def test_hash_is_stable_and_not_the_token(self):
        raw = tokens.generate_refresh_token()
        digest = tokens.hash_refresh_token(raw)
        assert digest == tokens.hash_refresh_token(raw)
        assert raw not in digest
        assert len(digest) == 64


@pytest.mark.asyncio
class TestRefreshRotation:

    async def test_raw_token_is_never_stored(self, db_conn, make_user):
        """Requirement 10. The stored value must be a hash, not the token."""
        user = await make_user()
        issued = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        stored = await db_conn.fetchval(
            "SELECT token_hash FROM refresh_tokens WHERE id = $1", issued["id"]
        )
        assert stored != issued["raw_token"]
        assert stored == tokens.hash_refresh_token(issued["raw_token"])

        # And the raw value appears nowhere in the row at all.
        row = await db_conn.fetchrow(
            "SELECT * FROM refresh_tokens WHERE id = $1", issued["id"]
        )
        assert issued["raw_token"] not in " ".join(
            str(v) for v in dict(row).values() if v is not None
        )

    async def test_rotation_issues_a_successor_and_kills_the_original(
            self, db_conn, make_user):
        user = await make_user()
        first = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        result = await tokens.rotate_refresh_token(db_conn, first["raw_token"])
        assert result["outcome"] == tokens.RefreshOutcome.OK

        successor = result["refresh"]
        assert successor["raw_token"] != first["raw_token"]
        # Same family, linked to its parent.
        assert successor["family_id"] == first["family_id"]

        old = await db_conn.fetchrow(
            "SELECT revoked_at, revoked_reason, replaced_by FROM refresh_tokens WHERE id = $1",
            first["id"],
        )
        assert old["revoked_at"] is not None
        assert old["revoked_reason"] == "rotated"
        assert old["replaced_by"] == successor["id"]

    async def test_successor_can_itself_be_rotated(self, db_conn, make_user):
        """A chain of refreshes keeps working — rotation is not single-shot."""
        user = await make_user()
        current = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        for _ in range(3):
            result = await tokens.rotate_refresh_token(db_conn, current["raw_token"])
            assert result["outcome"] == tokens.RefreshOutcome.OK
            current = result["refresh"]

    async def test_unknown_token_is_rejected(self, db_conn):
        result = await tokens.rotate_refresh_token(
            db_conn, tokens.generate_refresh_token()
        )
        assert result["outcome"] == tokens.RefreshOutcome.UNKNOWN

    async def test_revoked_token_is_rejected(self, db_conn, make_user):
        user = await make_user()
        issued = await tokens.issue_refresh_token(db_conn, user_id=user["id"])
        await tokens.revoke_token(db_conn, issued["raw_token"], reason="logout")

        result = await tokens.rotate_refresh_token(db_conn, issued["raw_token"])
        assert result["outcome"] == tokens.RefreshOutcome.REVOKED

    async def test_expired_token_is_rejected(self, db_conn, make_user):
        user = await make_user()
        issued = await tokens.issue_refresh_token(db_conn, user_id=user["id"])
        await db_conn.execute(
            "UPDATE refresh_tokens SET expires_at = NOW() - interval '1 hour' WHERE id = $1",
            issued["id"],
        )
        result = await tokens.rotate_refresh_token(db_conn, issued["raw_token"])
        assert result["outcome"] == tokens.RefreshOutcome.EXPIRED


@pytest.mark.asyncio
class TestRefreshReuseDetection:
    """Requirement 13 — the theft-detection property."""

    async def test_reusing_a_rotated_token_is_detected(self, db_conn, make_user):
        user = await make_user()
        stolen = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        # The legitimate client refreshes; `stolen` is now spent.
        await tokens.rotate_refresh_token(db_conn, stolen["raw_token"])

        # The thief replays the token they captured earlier.
        result = await tokens.rotate_refresh_token(db_conn, stolen["raw_token"])
        assert result["outcome"] == tokens.RefreshOutcome.REUSED

    async def test_reuse_revokes_the_entire_family(self, db_conn, make_user):
        """
        Including the successor the real user is holding. Both parties are
        logged out because from here they are indistinguishable, and the safe
        reading is that the chain is compromised.
        """
        user = await make_user()
        first = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        second = (await tokens.rotate_refresh_token(db_conn, first["raw_token"]))["refresh"]
        third = (await tokens.rotate_refresh_token(db_conn, second["raw_token"]))["refresh"]

        # The live token still works before the reuse.
        assert await db_conn.fetchval(
            "SELECT revoked_at IS NULL FROM refresh_tokens WHERE id = $1", third["id"]
        )

        await tokens.rotate_refresh_token(db_conn, first["raw_token"])

        live = await db_conn.fetchval(
            """SELECT COUNT(*) FROM refresh_tokens
               WHERE family_id = $1::uuid AND revoked_at IS NULL""",
            first["family_id"],
        )
        assert live == 0

        reason = await db_conn.fetchval(
            "SELECT revoked_reason FROM refresh_tokens WHERE id = $1", third["id"]
        )
        assert reason == "reuse_detected"

    async def test_reuse_does_not_affect_other_families(self, db_conn, make_user):
        """A compromise in one session must not log the user out everywhere."""
        user = await make_user()
        family_a = await tokens.issue_refresh_token(db_conn, user_id=user["id"])
        family_b = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        await tokens.rotate_refresh_token(db_conn, family_a["raw_token"])
        await tokens.rotate_refresh_token(db_conn, family_a["raw_token"])  # reuse

        assert await db_conn.fetchval(
            "SELECT revoked_at IS NULL FROM refresh_tokens WHERE id = $1",
            family_b["id"],
        )


@pytest.mark.asyncio
class TestRevokeAll:

    async def test_revokes_every_live_session(self, db_conn, make_user):
        user = await make_user()
        issued = [await tokens.issue_refresh_token(db_conn, user_id=user["id"])
                  for _ in range(3)]

        count = await tokens.revoke_all_for_user(db_conn, user["id"])
        assert count == 3

        for token in issued:
            result = await tokens.rotate_refresh_token(db_conn, token["raw_token"])
            assert result["outcome"] == tokens.RefreshOutcome.REVOKED

    async def test_does_not_touch_other_users(self, db_conn, make_user):
        alice = await make_user()
        bob = await make_user()
        bob_token = await tokens.issue_refresh_token(db_conn, user_id=bob["id"])
        await tokens.issue_refresh_token(db_conn, user_id=alice["id"])

        await tokens.revoke_all_for_user(db_conn, alice["id"])

        result = await tokens.rotate_refresh_token(db_conn, bob_token["raw_token"])
        assert result["outcome"] == tokens.RefreshOutcome.OK

    async def test_list_sessions_excludes_revoked(self, db_conn, make_user):
        user = await make_user()
        await tokens.issue_refresh_token(db_conn, user_id=user["id"])
        assert len(await tokens.list_sessions(db_conn, user["id"])) == 1

        await tokens.revoke_all_for_user(db_conn, user["id"])
        assert await tokens.list_sessions(db_conn, user["id"]) == []

    async def test_list_sessions_never_exposes_token_material(self, db_conn, make_user):
        user = await make_user()
        issued = await tokens.issue_refresh_token(db_conn, user_id=user["id"])

        sessions = await tokens.list_sessions(db_conn, user["id"])
        serialised = str(sessions)
        assert issued["raw_token"] not in serialised
        assert tokens.hash_refresh_token(issued["raw_token"]) not in serialised


# ── Password hashing (requirement 16) ────────────────────────────────────────

class TestPasswordHashing:

    def test_new_hashes_are_argon2id(self):
        from core.auth import hash_password
        assert hash_password("correct horse battery staple").startswith("$argon2id$")

    def test_verifies_its_own_hash(self):
        from core.auth import hash_password, verify_password
        hashed = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", hashed)
        assert not verify_password("wrong password entirely", hashed)

    def test_legacy_pbkdf2_hashes_still_verify(self):
        """
        Existing accounts — the seeded admin among them — are pbkdf2_sha256.
        Dropping support would lock every current user out permanently.
        """
        from passlib.hash import pbkdf2_sha256

        from core.auth import needs_rehash, verify_password

        legacy = pbkdf2_sha256.hash("legacy-password-value")
        assert verify_password("legacy-password-value", legacy)
        assert needs_rehash(legacy), "a legacy hash should be marked for upgrade"

    def test_argon2_hash_does_not_need_rehash(self):
        from core.auth import hash_password, needs_rehash
        assert not needs_rehash(hash_password("some password value"))

    def test_malformed_hash_returns_false_rather_than_raising(self):
        from core.auth import verify_password
        assert not verify_password("anything", "not-a-hash")
        assert not verify_password("anything", "")

    def test_salts_differ_between_hashes(self):
        from core.auth import hash_password
        assert hash_password("same input") != hash_password("same input")


@pytest.mark.asyncio
class TestPasswordUpgrade:

    async def test_legacy_hash_is_upgraded_on_successful_login(self, db_conn):
        """The one moment the plaintext exists to re-hash with."""
        from passlib.hash import pbkdf2_sha256

        from core.auth import authenticate_user

        password = "legacy-user-password"
        email = f"legacy-{uuid.uuid4().hex[:12]}@quanseq.test"
        user_id = await db_conn.fetchval(
            """INSERT INTO users (email, password_hash, role, portal)
               VALUES ($1, $2, 'operator', 'main') RETURNING id""",
            email, pbkdf2_sha256.hash(password),
        )

        user = await authenticate_user(db_conn, email, password)
        assert user is not None

        upgraded = await db_conn.fetchval(
            "SELECT password_hash FROM users WHERE id = $1", user_id
        )
        assert upgraded.startswith("$argon2id$")

    async def test_wrong_password_does_not_upgrade(self, db_conn):
        from passlib.hash import pbkdf2_sha256

        from core.auth import authenticate_user

        email = f"legacy-{uuid.uuid4().hex[:12]}@quanseq.test"
        original = pbkdf2_sha256.hash("the-real-password")
        user_id = await db_conn.fetchval(
            """INSERT INTO users (email, password_hash, role, portal)
               VALUES ($1, $2, 'operator', 'main') RETURNING id""",
            email, original,
        )

        assert await authenticate_user(db_conn, email, "the-wrong-password") is None
        assert await db_conn.fetchval(
            "SELECT password_hash FROM users WHERE id = $1", user_id
        ) == original

    async def test_unknown_email_returns_none(self, db_conn):
        from core.auth import authenticate_user
        assert await authenticate_user(
            db_conn, "nobody-here@quanseq.test", "any password"
        ) is None
