"""Tests for POST /api/register"""


class TestRegister:

    def test_register_success(self, client):
        """New user registers and receives a JWT."""
        res = client.post("/api/register", json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "securepass1",
        })
        assert res.status_code == 201
        body = res.get_json()
        assert "token" in body
        assert body["expiresIn"] == 3600

    def test_register_missing_username(self, client):
        """Missing username returns 400."""
        res = client.post("/api/register", json={
            "email": "new@example.com",
            "password": "securepass1",
        })
        assert res.status_code == 400

    def test_register_missing_email(self, client):
        """Missing email returns 400."""
        res = client.post("/api/register", json={
            "username": "newuser",
            "password": "securepass1",
        })
        assert res.status_code == 400

    def test_register_missing_password(self, client):
        """Missing password returns 400."""
        res = client.post("/api/register", json={
            "username": "newuser",
            "email": "new@example.com",
        })
        assert res.status_code == 400

    def test_register_invalid_email(self, client):
        """Malformed email returns 400."""
        res = client.post("/api/register", json={
            "username": "newuser",
            "email": "not-an-email",
            "password": "securepass1",
        })
        assert res.status_code == 400

    def test_register_password_too_short(self, client):
        """Password shorter than 8 characters returns 400."""
        res = client.post("/api/register", json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "short",
        })
        assert res.status_code == 400

    def test_register_username_too_short(self, client):
        """Username shorter than 3 characters returns 400."""
        res = client.post("/api/register", json={
            "username": "ab",
            "email": "new@example.com",
            "password": "securepass1",
        })
        assert res.status_code == 400

    def test_register_duplicate_username(self, client):
        """Registering with an already-used username returns 409."""
        res = client.post("/api/register", json={
            "username": "testuser",
            "email": "other@example.com",
            "password": "securepass1",
        })
        assert res.status_code == 409
        assert "message" in res.get_json()

    def test_register_duplicate_email(self, client):
        """Registering with an already-used email returns 409."""
        res = client.post("/api/register", json={
            "username": "brandnewuser",
            "email": "test@example.com",
            "password": "securepass1",
        })
        assert res.status_code == 409

    def test_register_non_json_body(self, client):
        """Non-JSON Content-Type returns 400."""
        res = client.post(
            "/api/register",
            data="username=foo&email=foo@bar.com&password=pass1234",
            content_type="application/x-www-form-urlencoded",
        )
        assert res.status_code == 400
