"""
tests/test_auth_api.py — the authentication endpoints over HTTP.

Complements test_auth_tokens.py, which exercises the token primitives directly.
These tests drive the real routes through TestClient with authentication fully
enabled — nothing is stubbed, because the auth layer is what is under test.

A note on the database: `api_client` rolls back each request's transaction, so a
row written by one request is not visible to the next. Tests that need a user to
survive across requests use the `live_user` fixture, which commits and cleans
up afterwards. Anything asserting on persisted refresh-token state belongs in
test_auth_tokens.py instead, against `db_conn`.
"""

import pytest

from core.config import settings
from core.scopes import SYSTEM_ADMIN, TLS_ADMIN, TLS_READ


# ── Login ────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_successful_login_returns_an_access_token_and_scopes(
            self, api_client, live_user, login):
        user = live_user(role="operator", portal="tls")
        response = login(user)

        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["expires_in"] == settings.ACCESS_TOKEN_TTL_MINUTES * 60
        assert body["portal"] == "tls"
        assert TLS_ADMIN in body["scopes"]
        assert SYSTEM_ADMIN not in body["scopes"]

    def test_access_token_is_accepted_by_a_protected_endpoint(
            self, api_client, live_user, login):
        user = live_user(role="operator", portal="main")
        token = login(user).json()["access_token"]

        response = api_client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["email"] == user["email"]
        assert body["auth_method"] == "access_token"
        assert TLS_READ in body["scopes"]

    def test_invalid_password_is_rejected(self, api_client, live_user):
        user = live_user()
        response = api_client.post(
            "/api/auth/login?use_cookie=false",
            data={"username": user["email"], "password": "definitely-not-it"},
        )
        assert response.status_code == 401

    def test_unknown_email_is_rejected(self, api_client):
        response = api_client.post(
            "/api/auth/login?use_cookie=false",
            data={"username": "nobody@quansec.test", "password": "whatever-value"},
        )
        assert response.status_code == 401

    def test_unknown_email_and_wrong_password_are_indistinguishable(
            self, api_client, live_user):
        """
        Requirement 17 — generic errors, so login cannot be used to enumerate
        which email addresses have accounts.
        """
        user = live_user()
        wrong_password = api_client.post(
            "/api/auth/login?use_cookie=false",
            data={"username": user["email"], "password": "definitely-not-it"},
        )
        no_such_user = api_client.post(
            "/api/auth/login?use_cookie=false",
            data={"username": "nobody@quansec.test", "password": "definitely-not-it"},
        )

        assert wrong_password.status_code == no_such_user.status_code == 401
        assert wrong_password.json()["detail"] == no_such_user.json()["detail"]

    def test_no_token_is_rejected(self, api_client):
        assert api_client.get("/api/auth/me").status_code == 401

    def test_garbage_token_is_rejected(self, api_client):
        response = api_client.get(
            "/api/auth/me", headers={"Authorization": "Bearer not.a.token"}
        )
        assert response.status_code == 401

    def test_refresh_token_is_not_in_the_body_for_cookie_clients(
            self, api_client, live_user, login):
        """
        Requirement 14 — a browser must not receive the refresh token anywhere
        JavaScript can read it.
        """
        user = live_user()
        body = login(user, use_cookie=True).json()

        assert body["refresh_token"] is None
        assert settings.REFRESH_COOKIE_NAME in api_client.cookies

    def test_refresh_cookie_flags_are_set(self, api_client, live_user, login):
        user = live_user()
        response = login(user, use_cookie=True)

        cookie_header = " ".join(
            value for key, value in response.headers.items()
            if key.lower() == "set-cookie"
        )
        refresh_cookie = [
            part for part in response.headers.get_list("set-cookie")
            if part.startswith(settings.REFRESH_COOKIE_NAME)
        ]
        assert refresh_cookie, "no refresh cookie was set"
        assert "HttpOnly" in refresh_cookie[0]
        assert f"Path={settings.REFRESH_COOKIE_PATH}" in refresh_cookie[0]
        assert "SameSite" in cookie_header

    def test_non_cookie_client_receives_the_refresh_token_in_the_body(
            self, api_client, live_user, login):
        user = live_user()
        body = login(user, use_cookie=False).json()
        assert body["refresh_token"]


# ── Portal scoping ───────────────────────────────────────────────────────────

class TestPortalScoping:

    def test_matching_portal_is_accepted(self, api_client, live_user, login):
        user = live_user(role="operator", portal="tls")
        assert login(user, portal="tls").status_code == 200

    def test_wrong_portal_is_rejected(self, api_client, live_user, login):
        user = live_user(role="operator", portal="ssh")
        assert login(user, portal="tls").status_code == 401

    def test_wrong_portal_looks_like_bad_credentials(
            self, api_client, live_user, login):
        """
        A distinct "not registered for this portal" message would confirm the
        account exists, defeating the uniform error.
        """
        user = live_user(role="operator", portal="ssh")
        wrong_portal = login(user, portal="tls")
        bad_password = api_client.post(
            "/api/auth/login-scoped?portal=tls&use_cookie=false",
            data={"username": user["email"], "password": "wrong-password-here"},
        )
        assert wrong_portal.json()["detail"] == bad_password.json()["detail"]

    def test_admin_reaches_any_portal(self, api_client, live_user, login):
        admin = live_user(role="admin", portal="ipsec")
        assert login(admin, portal="tls").status_code == 200

    def test_main_portal_user_reaches_any_portal(self, api_client, live_user, login):
        user = live_user(role="operator", portal="main")
        assert login(user, portal="tls").status_code == 200


# ── Scope enforcement on the TLS module ──────────────────────────────────────

class TestScopeEnforcement:
    """
    Requirements 5, 6 and 7, verified against the real TLS routes.

    These assert on authorization only. A 503 from a TLS endpoint means the
    request was authorized and the data plane is simply not running, which is a
    pass for this purpose — the failure mode being tested for is 401/403.
    """

    READ_ENDPOINTS = [
        "/api/tls/status",
        "/api/tls/readiness",
        "/api/tls/sessions",
        "/api/tls/policy",
        "/api/tls/events",
    ]

    ADMIN_ENDPOINTS = [
        "/api/tls/probe",
        "/api/tls/tests/hybrid-downgrade",
        "/api/tls/tests/tls12-downgrade",
        "/api/tls/tests/cipher-downgrade",
        "/api/tls/policy/apply",
        "/api/tls/service/reload",
    ]

    @pytest.mark.parametrize("path", READ_ENDPOINTS)
    def test_read_endpoints_reject_anonymous_callers(self, api_client, path):
        assert api_client.get(path).status_code == 401

    @pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
    def test_admin_endpoints_reject_anonymous_callers(self, api_client, path):
        assert api_client.post(path).status_code == 401

    @pytest.mark.parametrize("path", READ_ENDPOINTS)
    def test_operator_may_read(self, api_client, live_user, login, path):
        user = live_user(role="operator", portal="main")
        token = login(user).json()["access_token"]
        response = api_client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code != 403, f"tls:read should permit {path}"
        assert response.status_code != 401

    @pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
    def test_read_only_operator_is_denied_admin_actions(
            self, api_client, live_user, login, path):
        """The wrong-scope case. An operator on `main` holds tls:read, not tls:admin."""
        user = live_user(role="operator", portal="main")
        token = login(user).json()["access_token"]

        response = api_client.post(path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403, f"{path} must require tls:admin"
        assert "tls:admin" in response.json()["detail"]

    @pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
    def test_tls_portal_operator_is_permitted_admin_actions(
            self, api_client, live_user, login, path):
        """A portal-scoped operator holds tls:admin and must pass the scope check."""
        user = live_user(role="operator", portal="tls")
        token = login(user).json()["access_token"]

        response = api_client.post(path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code != 403, f"tls:admin should permit {path}"

    @pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
    def test_admin_is_permitted_admin_actions(
            self, api_client, live_user, login, path):
        admin = live_user(role="admin", portal="main")
        token = login(admin).json()["access_token"]

        response = api_client.post(path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code != 403

    def test_ssh_operator_cannot_administer_tls(self, api_client, live_user, login):
        """Cross-module isolation: ssh:admin must not carry tls:admin."""
        user = live_user(role="operator", portal="ssh")
        token = login(user).json()["access_token"]

        response = api_client.post(
            "/api/tls/probe", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403

    def test_admin_only_user_management(self, api_client, live_user, login):
        user = live_user(role="operator", portal="tls")
        token = login(user).json()["access_token"]

        response = api_client.get(
            "/api/auth/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403


# ── Backward compatibility ───────────────────────────────────────────────────

class TestBackwardCompatibility:
    """
    Requirement 24 and the SSH/IPsec preservation constraint.

    `require_user` and `require_admin` still guard the SSH and IPsec routers.
    These confirm the migration did not silently change who may reach them.
    """

    def test_ssh_routes_still_require_authentication(self, api_client):
        assert api_client.get("/api/ssh/stats").status_code == 401

    def test_ipsec_routes_still_require_authentication(self, api_client):
        assert api_client.post("/api/ipsec/attacks/downgrade").status_code == 401

    def test_operator_still_reaches_require_user_routes(
            self, api_client, live_user, login):
        """An operator could read SSH before the migration and must still be able to."""
        user = live_user(role="operator", portal="main")
        token = login(user).json()["access_token"]

        response = api_client.get(
            "/api/ssh/stats", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code not in (401, 403)

    def test_operator_still_denied_require_admin_routes(
            self, api_client, live_user, login):
        user = live_user(role="operator", portal="main")
        token = login(user).json()["access_token"]

        response = api_client.post(
            "/api/ssh/policies/apply",
            headers={"Authorization": f"Bearer {token}"}, json={},
        )
        assert response.status_code == 403


# ── Refresh, logout and revoke-all over HTTP ─────────────────────────────────

class TestRefreshEndpoint:

    def test_refresh_returns_a_new_access_token(
            self, committing_api_client, live_user, committing_login):
        """Uses the committing client: the login and the refresh are two requests."""
        user = live_user()
        first = committing_login(user).json()

        response = committing_api_client.post(
            "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["access_token"]
        # Rotation: the returned refresh token is a new one.
        assert body["refresh_token"] != first["refresh_token"]

    def test_refresh_without_a_token_is_rejected(self, api_client):
        assert api_client.post("/api/auth/refresh", json={}).status_code == 401

    def test_refresh_with_a_bogus_token_is_rejected(self, api_client):
        response = api_client.post(
            "/api/auth/refresh", json={"refresh_token": "not-a-real-token"}
        )
        assert response.status_code == 401

    def test_an_access_token_is_not_accepted_as_a_refresh_token(
            self, api_client, live_user, login):
        """Type confusion: the two token kinds must not be interchangeable."""
        user = live_user()
        access = login(user).json()["access_token"]

        response = api_client.post(
            "/api/auth/refresh", json={"refresh_token": access}
        )
        assert response.status_code == 401


class TestLogout:

    def test_logout_succeeds_without_an_access_token(self, api_client, live_user, login):
        """
        A user whose access token has expired must still be able to log out,
        or the refresh token stays live for its full lifetime.
        """
        user = live_user()
        refresh_token = login(user).json()["refresh_token"]

        response = api_client.post(
            "/api/auth/logout", json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200

    def test_logout_is_idempotent(self, api_client, live_user, login):
        user = live_user()
        refresh_token = login(user).json()["refresh_token"]

        api_client.post("/api/auth/logout", json={"refresh_token": refresh_token})
        second = api_client.post(
            "/api/auth/logout", json={"refresh_token": refresh_token}
        )
        assert second.status_code == 200

    def test_logout_with_no_token_still_succeeds(self, api_client):
        assert api_client.post("/api/auth/logout", json={}).status_code == 200


class TestRevokeAllEndpoint:

    def test_requires_authentication(self, api_client):
        assert api_client.post("/api/auth/revoke-all").status_code == 401

    def test_authenticated_caller_may_revoke(self, api_client, live_user, login):
        user = live_user()
        token = login(user).json()["access_token"]

        response = api_client.post(
            "/api/auth/revoke-all", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert "revoked" in response.json()

    def test_response_states_the_access_token_window(
            self, api_client, live_user, login):
        """
        Revoke-all cannot withdraw an already-issued access token. The response
        must say so rather than implying an immediate cut-off.
        """
        user = live_user()
        token = login(user).json()["access_token"]

        detail = api_client.post(
            "/api/auth/revoke-all", headers={"Authorization": f"Bearer {token}"}
        ).json()["detail"]
        assert str(settings.ACCESS_TOKEN_TTL_MINUTES) in detail


# ── CSRF ─────────────────────────────────────────────────────────────────────

class TestCsrf:
    """Requirement 14 — cookie-authenticated routes need the double-submit token."""

    def test_cookie_refresh_without_the_csrf_header_is_rejected(
            self, api_client, live_user, login):
        user = live_user()
        login(user, use_cookie=True)          # cookies land in the client jar

        response = api_client.post("/api/auth/refresh")
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"]

    def test_cookie_refresh_with_a_mismatched_csrf_header_is_rejected(
            self, api_client, live_user, login):
        user = live_user()
        login(user, use_cookie=True)

        response = api_client.post(
            "/api/auth/refresh",
            headers={settings.CSRF_HEADER_NAME: "a-value-that-does-not-match"},
        )
        assert response.status_code == 403

    def test_cookie_refresh_with_the_matching_csrf_header_succeeds(
            self, committing_api_client, live_user, committing_login):
        user = live_user()
        csrf_token = committing_login(user, use_cookie=True).json()["csrf_token"]

        response = committing_api_client.post(
            "/api/auth/refresh",
            headers={settings.CSRF_HEADER_NAME: csrf_token},
        )
        assert response.status_code == 200
        # Still withheld from the body on the cookie path.
        assert response.json()["refresh_token"] is None

    def test_body_token_clients_are_exempt_from_csrf(
            self, committing_api_client, live_user, committing_login):
        """
        A caller passing the token explicitly is not relying on ambient browser
        credentials, so there is nothing to forge and no header to demand.
        """
        user = live_user()
        refresh_token = committing_login(
            user, use_cookie=False).json()["refresh_token"]

        response = committing_api_client.post(
            "/api/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200

    def test_cookie_logout_without_csrf_is_rejected(
            self, api_client, live_user, login):
        user = live_user()
        login(user, use_cookie=True)
        assert api_client.post("/api/auth/logout").status_code == 403


# ── Introspection ────────────────────────────────────────────────────────────

class TestMe:

    def test_me_reports_scopes_and_descriptions(self, api_client, live_user, login):
        user = live_user(role="operator", portal="tls")
        token = login(user).json()["access_token"]

        body = api_client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).json()

        assert TLS_ADMIN in body["scopes"]
        assert body["scope_descriptions"][TLS_ADMIN]
        assert body["portal"] == "tls"

    def test_me_requires_authentication(self, api_client):
        assert api_client.get("/api/auth/me").status_code == 401

    def test_scope_matrix_is_available_to_any_authenticated_user(
            self, api_client, live_user, login):
        user = live_user(role="operator", portal="main")
        token = login(user).json()["access_token"]

        body = api_client.get(
            "/api/auth/scopes", headers={"Authorization": f"Bearer {token}"}
        ).json()
        assert SYSTEM_ADMIN in body["scopes"]
        assert "role_mapping" in body
