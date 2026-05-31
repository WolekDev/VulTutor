"""
Tests for account endpoints:
  GET    /api/account
  PUT    /api/account
  DELETE /api/account
"""


class TestGetAccount:

    def test_get_account_success(self, client, auth_headers):
        """Returns the authenticated user's profile."""
        res = client.get("/api/account", headers=auth_headers)
        assert res.status_code == 200
        body = res.get_json()
        assert body["username"] == "testuser"
        assert body["email"] == "test@example.com"
        assert "userId" in body

    def test_get_account_no_auth(self, client):
        """Request without token returns 401."""
        res = client.get("/api/account")
        assert res.status_code == 401


class TestUpdateAccount:

    def test_update_username(self, client, auth_headers):
        """Username can be updated successfully."""
        res = client.put("/api/account", json={"username": "updateduser"}, headers=auth_headers)
        assert res.status_code == 200
        assert res.get_json()["username"] == "updateduser"

    def test_update_email(self, client, auth_headers):
        """Email can be updated successfully."""
        res = client.put("/api/account", json={"email": "updated@example.com"}, headers=auth_headers)
        assert res.status_code == 200
        assert res.get_json()["email"] == "updated@example.com"

    def test_update_password(self, client, auth_headers):
        """Password can be changed; new password works for login."""
        client.put("/api/account", json={"password": "newpassword99"}, headers=auth_headers)
        res = client.post("/api/sessions", json={
            "username": "testuser",
            "password": "newpassword99",
        })
        assert res.status_code == 201

    def test_update_all_fields(self, client, auth_headers):
        """All three fields can be updated at once."""
        res = client.put("/api/account", json={
            "username": "allnew",
            "email": "allnew@example.com",
            "password": "allnewpass99",
        }, headers=auth_headers)
        assert res.status_code == 200
        body = res.get_json()
        assert body["username"] == "allnew"
        assert body["email"] == "allnew@example.com"

    def test_update_no_fields_returns_400(self, client, auth_headers):
        """Sending an empty update object returns 400."""
        res = client.put("/api/account", json={}, headers=auth_headers)
        assert res.status_code == 400

    def test_update_username_too_short(self, client, auth_headers):
        """Username shorter than 3 characters returns 400."""
        res = client.put("/api/account", json={"username": "ab"}, headers=auth_headers)
        assert res.status_code == 400

    def test_update_invalid_email(self, client, auth_headers):
        """Malformed email returns 400."""
        res = client.put("/api/account", json={"email": "not-an-email"}, headers=auth_headers)
        assert res.status_code == 400

    def test_update_password_too_short(self, client, auth_headers):
        """Password shorter than 8 characters returns 400."""
        res = client.put("/api/account", json={"password": "short"}, headers=auth_headers)
        assert res.status_code == 400

    def test_update_duplicate_username(self, client, auth_headers):
        """Taking another user's username returns 409."""
        # Create a second user first
        client.post("/api/register", json={
            "username": "otheruser",
            "email": "other@example.com",
            "password": "otherpass99",
        })
        res = client.put("/api/account", json={"username": "otheruser"}, headers=auth_headers)
        assert res.status_code == 409

    def test_update_duplicate_email(self, client, auth_headers):
        """Taking another user's email returns 409."""
        client.post("/api/register", json={
            "username": "otheruser2",
            "email": "other2@example.com",
            "password": "otherpass99",
        })
        res = client.put("/api/account", json={"email": "other2@example.com"}, headers=auth_headers)
        assert res.status_code == 409

    def test_update_non_json_body(self, client, auth_headers):
        """Non-JSON Content-Type returns 400."""
        res = client.put(
            "/api/account",
            data="username=newname",
            content_type="application/x-www-form-urlencoded",
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_update_no_auth(self, client):
        """Request without token returns 401."""
        res = client.put("/api/account", json={"username": "hacker"})
        assert res.status_code == 401


class TestDeleteAccount:

    def test_delete_account_success(self, client, auth_headers):
        """Account is deleted and returns 204."""
        res = client.delete("/api/account", headers=auth_headers)
        assert res.status_code == 204
        assert res.data == b""

    def test_deleted_account_cannot_login(self, client, auth_headers):
        """After deletion the credentials no longer work."""
        client.delete("/api/account", headers=auth_headers)
        res = client.post("/api/sessions", json={
            "username": "testuser",
            "password": "password123",
        })
        assert res.status_code == 401

    def test_delete_no_auth(self, client):
        """Request without token returns 401."""
        res = client.delete("/api/account")
        assert res.status_code == 401
