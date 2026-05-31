"""Tests for POST /api/sessions (login) and DELETE /api/sessions (logout)"""


class TestLogin:

    def test_login_success(self, client):
        """Valid credentials return 201 with a JWT."""
        res = client.post("/api/sessions", json={
            "username": "testuser",
            "password": "password123",
        })
        assert res.status_code == 201
        body = res.get_json()
        assert "token" in body
        assert body["expiresIn"] == 3600

    def test_login_wrong_password(self, client):
        """Wrong password returns 401."""
        res = client.post("/api/sessions", json={
            "username": "testuser",
            "password": "wrongpassword",
        })
        assert res.status_code == 401
        assert "message" in res.get_json()

    def test_login_nonexistent_user(self, client):
        """Unknown username returns 401."""
        res = client.post("/api/sessions", json={
            "username": "nobody",
            "password": "password123",
        })
        assert res.status_code == 401

    def test_login_missing_username(self, client):
        """Missing username field returns 400."""
        res = client.post("/api/sessions", json={"password": "password123"})
        assert res.status_code == 400

    def test_login_missing_password(self, client):
        """Missing password field returns 400."""
        res = client.post("/api/sessions", json={"username": "testuser"})
        assert res.status_code == 400

    def test_login_empty_body(self, client):
        """Empty JSON body returns 400."""
        res = client.post("/api/sessions", json={})
        assert res.status_code == 400

    def test_login_non_json_body(self, client):
        """Non-JSON Content-Type returns 400."""
        res = client.post(
            "/api/sessions",
            data="username=testuser&password=password123",
            content_type="application/x-www-form-urlencoded",
        )
        assert res.status_code == 400


class TestLogout:

    def test_logout_success(self, client, auth_headers):
        """Valid token is revoked and returns 204."""
        res = client.delete("/api/sessions", headers=auth_headers)
        assert res.status_code == 204
        assert res.data == b""

    def test_logout_no_token(self, client):
        """Request without a token returns 401."""
        res = client.delete("/api/sessions")
        assert res.status_code == 401

    def test_logout_revokes_token(self, client, auth_headers):
        """Token used after logout is rejected with 401."""
        client.delete("/api/sessions", headers=auth_headers)
        # Same token should now be refused on a protected endpoint
        res = client.get("/api/home", headers=auth_headers)
        assert res.status_code == 401

    def test_logout_invalid_token(self, client):
        """Malformed token returns 401."""
        res = client.delete("/api/sessions", headers={"Authorization": "Bearer not.a.valid.token"})
        assert res.status_code == 401
