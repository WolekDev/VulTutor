"""Tests for GET /api/home"""


class TestHome:

    def test_home_returns_dashboard_data(self, client, auth_headers):
        """Authenticated request returns username, vulnerabilities, and CVEs."""
        res = client.get("/api/home", headers=auth_headers)
        assert res.status_code == 200
        body = res.get_json()
        assert body["username"] == "testuser"
        assert isinstance(body["vulnerabilities"], list)
        assert isinstance(body["cves"], list)

    def test_home_vulnerability_shape(self, client, auth_headers):
        """Each vulnerability entry contains expected fields."""
        res = client.get("/api/home", headers=auth_headers)
        vuln = res.get_json()["vulnerabilities"][0]
        assert "vulnId" in vuln
        assert "name" in vuln
        assert "progress" in vuln
        assert "ctfCompleted" in vuln
        assert "questionsCompleted" in vuln
        assert "questionsTotal" in vuln

    def test_home_initial_progress_is_zero(self, client, auth_headers):
        """Progress and completion start at zero for a fresh user."""
        res = client.get("/api/home", headers=auth_headers)
        vuln = res.get_json()["vulnerabilities"][0]
        assert vuln["progress"] == 0.0
        assert vuln["ctfCompleted"] is False
        assert vuln["questionsCompleted"] == 0

    def test_home_cve_shape(self, client, auth_headers):
        """Each CVE entry contains a cveId field."""
        res = client.get("/api/home", headers=auth_headers)
        cve = res.get_json()["cves"][0]
        assert "cveId" in cve

    def test_home_no_auth(self, client):
        """Request without a token returns 401."""
        res = client.get("/api/home")
        assert res.status_code == 401

    def test_home_invalid_token(self, client):
        """Request with a malformed token returns 401."""
        res = client.get("/api/home", headers={"Authorization": "Bearer garbage"})
        assert res.status_code == 401
