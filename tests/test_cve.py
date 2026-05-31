"""Tests for GET /api/cve/{cveId}"""


class TestCVE:

    def test_get_cve_success(self, client, auth_headers):
        """Returns CVE details including related vulnerabilities."""
        res = client.get("/api/cve/CVE-2021-99999", headers=auth_headers)
        assert res.status_code == 200
        body = res.get_json()
        assert body["cveId"] == "CVE-2021-99999"
        assert "description" in body
        assert isinstance(body["relatedVulnerabilities"], list)

    def test_get_cve_related_vulnerabilities(self, client, auth_headers):
        """The seeded CVE is linked to the test vulnerability."""
        res = client.get("/api/cve/CVE-2021-99999", headers=auth_headers)
        related = res.get_json()["relatedVulnerabilities"]
        assert len(related) == 1
        assert "vulnId" in related[0]
        assert "name" in related[0]

    def test_get_cve_not_found(self, client, auth_headers):
        """Non-existent CVE ID returns 404."""
        res = client.get("/api/cve/CVE-2000-00001", headers=auth_headers)
        assert res.status_code == 404
        assert res.get_json()["code"] == 404

    def test_get_cve_invalid_format_no_year(self, client, auth_headers):
        """CVE ID without the correct pattern returns 400."""
        res = client.get("/api/cve/NOTACVE-1234", headers=auth_headers)
        assert res.status_code == 400

    def test_get_cve_invalid_format_short_number(self, client, auth_headers):
        """CVE ID with fewer than 4 digits after the year returns 400."""
        res = client.get("/api/cve/CVE-2021-123", headers=auth_headers)
        assert res.status_code == 400

    def test_get_cve_no_auth(self, client):
        """Request without token returns 401."""
        res = client.get("/api/cve/CVE-2021-99999")
        assert res.status_code == 401

    def test_get_cve_invalid_token(self, client):
        """Request with malformed token returns 401."""
        res = client.get(
            "/api/cve/CVE-2021-99999",
            headers={"Authorization": "Bearer notavalidtoken"},
        )
        assert res.status_code == 401
