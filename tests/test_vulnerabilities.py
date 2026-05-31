"""
Tests for vulnerability endpoints:
  GET  /api/vulnerabilities/{vulnId}/description
  GET  /api/vulnerabilities/{vulnId}/questions
  POST /api/vulnerabilities/{vulnId}/questions/{questionId}
"""


class TestVulnerabilityDescription:

    def test_get_description_success(self, client, auth_headers, ids):
        """Returns vulnerability name and description."""
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/description",
            headers=auth_headers,
        )
        assert res.status_code == 200
        body = res.get_json()
        assert body["vulnId"] == ids["vuln_id"]
        assert "name" in body
        assert "description" in body

    def test_get_description_not_found(self, client, auth_headers):
        """Non-existent vulnId returns 404."""
        res = client.get("/api/vulnerabilities/9999/description", headers=auth_headers)
        assert res.status_code == 404
        assert res.get_json()["code"] == 404

    def test_get_description_no_auth(self, client, ids):
        """Request without token returns 401."""
        res = client.get(f"/api/vulnerabilities/{ids['vuln_id']}/description")
        assert res.status_code == 401


class TestVulnerabilityQuestions:

    def test_get_questions_success(self, client, auth_headers, ids):
        """Returns list of questions with hints."""
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions",
            headers=auth_headers,
        )
        assert res.status_code == 200
        body = res.get_json()
        assert body["vulnId"] == ids["vuln_id"]
        assert isinstance(body["questions"], list)
        assert len(body["questions"]) == 1

    def test_question_shape(self, client, auth_headers, ids):
        """Each question has expected fields including hints."""
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions",
            headers=auth_headers,
        )
        q = res.get_json()["questions"][0]
        assert "questionId" in q
        assert "questionNumber" in q
        assert "question" in q
        assert "completed" in q
        assert isinstance(q["hints"], list)

    def test_hint_shape(self, client, auth_headers, ids):
        """Each hint has hintId, hintNumber, and hint text."""
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions",
            headers=auth_headers,
        )
        hint = res.get_json()["questions"][0]["hints"][0]
        assert "hintId" in hint
        assert "hintNumber" in hint
        assert "hint" in hint

    def test_question_initially_not_completed(self, client, auth_headers, ids):
        """Questions start as not completed for a fresh user."""
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions",
            headers=auth_headers,
        )
        assert res.get_json()["questions"][0]["completed"] is False

    def test_get_questions_not_found(self, client, auth_headers):
        """Non-existent vulnId returns 404."""
        res = client.get("/api/vulnerabilities/9999/questions", headers=auth_headers)
        assert res.status_code == 404

    def test_get_questions_no_auth(self, client, ids):
        """Request without token returns 401."""
        res = client.get(f"/api/vulnerabilities/{ids['vuln_id']}/questions")
        assert res.status_code == 401


class TestSubmitAnswer:

    def test_correct_answer(self, client, auth_headers, ids):
        """Correct answer returns correct=True and marks question done."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            json={"answer": "testanswer"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        body = res.get_json()
        assert body["correct"] is True
        assert "message" in body

    def test_correct_answer_case_insensitive(self, client, auth_headers, ids):
        """Answer matching is case-insensitive."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            json={"answer": "TESTANSWER"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.get_json()["correct"] is True

    def test_correct_answer_marks_question_complete(self, client, auth_headers, ids):
        """After a correct answer the question shows as completed."""
        client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            json={"answer": "testanswer"},
            headers=auth_headers,
        )
        res = client.get(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions",
            headers=auth_headers,
        )
        assert res.get_json()["questions"][0]["completed"] is True

    def test_incorrect_answer(self, client, auth_headers, ids):
        """Wrong answer returns correct=False with a message."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            json={"answer": "wronganswer"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.get_json()["correct"] is False

    def test_missing_answer_field(self, client, auth_headers, ids):
        """Missing answer field returns 400."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            json={},
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_non_json_body(self, client, auth_headers, ids):
        """Non-JSON body returns 400."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            data="answer=testanswer",
            content_type="application/x-www-form-urlencoded",
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_vuln_not_found(self, client, auth_headers, ids):
        """Non-existent vulnId returns 404."""
        res = client.post(
            f"/api/vulnerabilities/9999/questions/{ids['question_id']}",
            json={"answer": "testanswer"},
            headers=auth_headers,
        )
        assert res.status_code == 404

    def test_question_not_found(self, client, auth_headers, ids):
        """Non-existent questionId returns 404."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/9999",
            json={"answer": "testanswer"},
            headers=auth_headers,
        )
        assert res.status_code == 404

    def test_no_auth(self, client, ids):
        """Request without token returns 401."""
        res = client.post(
            f"/api/vulnerabilities/{ids['vuln_id']}/questions/{ids['question_id']}",
            json={"answer": "testanswer"},
        )
        assert res.status_code == 401
