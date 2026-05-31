"""
Tests for CTF endpoints:
  GET  /api/vulnerabilities/{vulnId}/ctf
  POST /api/vulnerabilities/{vulnId}/ctf
"""


class TestGetCTF:

    def test_get_ctf_success(self, client, auth_headers, ids):
        """Returns CTF details for a vulnerability that has one."""
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            headers=auth_headers,
        )
        assert res.status_code == 200
        body = res.get_json()
        assert "ctfId" in body
        assert "description" in body
        assert "path" in body
        assert body["completed"] is False

    def test_get_ctf_not_found_vuln(self, client, auth_headers):
        """Non-existent vulnId returns 404."""
        res = client.get("/api/vulnerabilities/9999/ctf", headers=auth_headers)
        assert res.status_code == 404

    def test_get_ctf_no_auth(self, client, ids):
        """Request without token returns 401."""
        res = client.get(f"/api/vulnerabilities/{ids['vuln_id']}/ctf")
        assert res.status_code == 401

    def test_get_ctf_completed_after_solve(self, client, auth_headers, ids):
        """completed field becomes True after the correct flag is submitted."""
        client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            json={"flag": "FLAG{test_flag}"},
            headers=auth_headers,
        )
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            headers=auth_headers,
        )
        assert res.get_json()["completed"] is True


class TestSubmitFlag:

    def test_correct_flag(self, client, auth_headers, ids):
        """Correct flag returns correct=True."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            json={"flag": "FLAG{test_flag}"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        body = res.get_json()
        assert body["correct"] is True
        assert "message" in body

    def test_incorrect_flag(self, client, auth_headers, ids):
        """Wrong flag returns correct=False."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            json={"flag": "FLAG{wrong_flag}"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.get_json()["correct"] is False

    def test_correct_flag_marks_ctf_complete_on_dashboard(self, client, auth_headers, ids):
        """Solving the CTF sets ctfCompleted=True on the home dashboard."""
        client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            json={"flag": "FLAG{test_flag}"},
            headers=auth_headers,
        )
        res = client.get("/api/home", headers=auth_headers)
        vuln = res.get_json()["vulnerabilities"][0]
        assert vuln["ctfCompleted"] is True
        assert vuln["progress"] == 1.0

    def test_missing_flag_field(self, client, auth_headers, ids):
        """Missing flag field returns 400."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            json={},
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_non_json_body(self, client, auth_headers, ids):
        """Non-JSON body returns 400."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            data="flag=FLAG{test_flag}",
            content_type="application/x-www-form-urlencoded",
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_vuln_not_found(self, client, auth_headers):
        """Non-existent vulnId returns 404."""
        res = client.post(
            "/api/vulnerabilities/9999/ctf",
            json={"flag": "FLAG{test_flag}"},
            headers=auth_headers,
        )
        assert res.status_code == 404

    def test_no_auth(self, client, ids):
        """Request without token returns 401."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/ctf",
            json={"flag": "FLAG{test_flag}"},
        )
        assert res.status_code == 401
