"""
Shared pytest fixtures for VulTutor API tests.

Each test function gets a fresh in-memory SQLite database seeded with:
  - One user        : testuser / password123
  - One CTF         : flag = FLAG{test_flag}
  - One Vulnerability linked to the CTF
  - One Question    (answer = "testanswer")
  - One Hint        for that question
  - One CVE         : CVE-2021-99999
  - One CVEVulnerability link
"""

import pytest
from werkzeug.security import generate_password_hash

from app import create_app, db, token_blocklist
from app.models import (
    Account, CTF, Vulnerability, Question, Hint, CVE, CVEVulnerability,
)
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test-jwt-secret-key-at-least-32-bytes!!"
    SECRET_KEY = "test-secret-key-at-least-32-bytes!!"


# ---------------------------------------------------------------------------
# App / DB fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    flask_app = create_app(TestConfig)
    token_blocklist.clear()

    with flask_app.app_context():
        db.create_all()
        _seed()
        yield flask_app
        db.session.remove()
        db.drop_all()

    token_blocklist.clear()


def _seed():
    user = Account(
        username="testuser",
        email="test@example.com",
        passwordHash=generate_password_hash("password123"),
    )
    db.session.add(user)

    ctf = CTF(
        description="Exploit this test CTF challenge.",
        path="/challenges/test.zip",
        flag="FLAG{test_flag}",
    )
    db.session.add(ctf)
    db.session.flush()

    vuln = Vulnerability(
        name="Test Vulnerability",
        description="A deliberately vulnerable test module.",
        ctfId=ctf.ctfId,
    )
    db.session.add(vuln)
    db.session.flush()

    question = Question(
        vulnId=vuln.vulnId,
        questionNumber=1,
        question="What is the test answer?",
        answer="testanswer",
    )
    db.session.add(question)
    db.session.flush()

    db.session.add(Hint(
        questionId=question.questionId,
        hintNumber=1,
        hint="Think carefully about the test.",
    ))

    cve = CVE(cveId="CVE-2021-99999", description="A fictional test CVE.")
    db.session.add(cve)
    db.session.flush()

    db.session.add(CVEVulnerability(cveId="CVE-2021-99999", vulnId=vuln.vulnId))
    db.session.commit()


# ---------------------------------------------------------------------------
# Client / auth helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_headers(client):
    """JWT headers for the seeded testuser."""
    res = client.post(
        "/api/sessions",
        json={"username": "testuser", "password": "password123"},
    )
    token = res.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def ids(app):
    """IDs of the seeded entities, looked up after commit."""
    vuln = Vulnerability.query.first()
    question = Question.query.first()
    cve = CVE.query.first()
    return {
        "vuln_id": vuln.vulnId,
        "question_id": question.questionId,
        "cve_id": cve.cveId,
        "ctf_id": vuln.ctfId,
    }
