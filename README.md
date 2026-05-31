<div align="center">
    <img src="static/img/LOGO.png", width="200">
    <h1>VulTutor</h1>
</div>

VulTutor is a cybersecurity learning platform inspired by [WebGoat](https://owasp.org/www-project-webgoat/).
Users explore intentionally vulnerable exercises, quiz questions with hints, CTF (Capture The Flag) challenges,
and real-world CVE references.

---

## Tech Stack

| Layer      | Technology                               |
|------------|------------------------------------------|
| Backend    | Python, Flask, SQLAlchemy, SQLite        |
| Auth       | Flask-JWT-Extended (Bearer tokens)       |
| Validation | Marshmallow schemas                      |
| Frontend   | Flask (Jinja2 templates), Bootstrap 5    |
| API Docs   | Swagger UI (flask-swagger-ui)            |

---

## Getting Started

### If you are on linux, just run init.sh and then run.sh

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Seed the database (first time only)

Populates the database with three vulnerability modules (SQL Injection, XSS, Path Traversal),
quiz questions, hints, CTF challenges, CVE records, and a test user account.

```bash
python seed.py
```

Test credentials created by the seed script:

| Field    | Value            |
|----------|------------------|
| Username | `student`        |
| Password | `password123`    |

> **Note:** Running `seed.py` again will **wipe and recreate** the database.

### 3. Start the server

```bash
python run.py
```

The app is served at **http://localhost:8080**.

---

## Application URLs

| URL                                                | Description                          |
|----------------------------------------------------|--------------------------------------|
| http://localhost:8080/                             | Redirects to login                   |
| http://localhost:8080/login                        | Sign in                              |
| http://localhost:8080/register                     | Create an account                    |
| http://localhost:8080/home                         | Dashboard (vulnerabilities + CVEs)   |
| http://localhost:8080/vulnerability/{id}           | Vulnerability description            |
| http://localhost:8080/vulnerability/{id}/questions | Quiz questions + hints               |
| http://localhost:8080/vulnerability/{id}/ctf       | CTF challenge                        |
| http://localhost:8080/cve/{cveId}                  | CVE detail page                      |
| http://localhost:8080/account                      | Account settings                     |

---

## API Documentation (Swagger UI)

Interactive API docs are available at:

**http://localhost:8080/docs/**

The raw OpenAPI 3.0 spec is served at:

**http://localhost:8080/api/openapi.yaml**

### Testing endpoints in Swagger UI

1. Open **http://localhost:8080/docs/** in your browser.
2. To test protected endpoints, first call **POST /api/sessions** (or **POST /api/register**) with a username and password - the response contains a `token`.
3. Click the **Authorize** button (padlock icon) at the top of the page.
4. Enter `Bearer <your_token>` in the **Value** field and click **Authorize**.
5. All subsequent requests in the UI will include the JWT automatically.

---

## API Summary

| Method   | Endpoint                                          | Auth | Description                        |
|----------|---------------------------------------------------|------|------------------------------------|
| `POST`   | `/api/register`                                   | No   | Create account (returns JWT)       |
| `POST`   | `/api/sessions`                                   | No   | Login (returns JWT)                |
| `DELETE` | `/api/sessions`                                   | Yes  | Logout (revokes token)             |
| `GET`    | `/api/home`                                       | Yes  | Dashboard data                     |
| `GET`    | `/api/vulnerabilities/{vulnId}/description`       | Yes  | Vulnerability description          |
| `GET`    | `/api/vulnerabilities/{vulnId}/questions`         | Yes  | Quiz questions + hints             |
| `POST`   | `/api/vulnerabilities/{vulnId}/questions/{qId}`   | Yes  | Submit answer                      |
| `GET`    | `/api/vulnerabilities/{vulnId}/ctf`               | Yes  | CTF challenge details              |
| `POST`   | `/api/vulnerabilities/{vulnId}/ctf`               | Yes  | Submit CTF flag                    |
| `GET`    | `/api/cve/{cveId}`                                | Yes  | CVE details                        |
| `GET`    | `/api/account`                                    | Yes  | View account profile               |
| `PUT`    | `/api/account`                                    | Yes  | Update username / email / password |
| `DELETE` | `/api/account`                                    | Yes  | Delete account                     |

---

## Project Structure

```
VulTutor/
├── run.py                  # Entry point
├── seed.py                 # Database seeder
├── config.py               # App configuration
├── requirements.txt
├── openapi.yaml            # OpenAPI 3.0 specification
│
├── app/
│   ├── __init__.py         # App factory + Swagger UI registration
│   ├── models.py           # SQLAlchemy ORM models
│   ├── validators.py       # Marshmallow input schemas
│   │
│   ├── api/                # REST API blueprint (/api)
│   │   ├── sessions.py
│   │   ├── register.py
│   │   ├── home.py
│   │   ├── vulnerabilities.py
│   │   ├── cve.py
│   │   └── account.py
│   │
│   └── frontend/           # HTML page blueprint (/)
│       └── routes.py
│
├── templates/              # Jinja2 templates
├── static/                 # CSS and JS assets
└── tests/                  # pytest unit tests
    ├── conftest.py          # Fixtures: in-memory DB, test client, auth helpers
    ├── test_register.py
    ├── test_sessions.py
    ├── test_home.py
    ├── test_vulnerabilities.py
    ├── test_ctf.py
    ├── test_cve.py
    └── test_account.py
```

---

## Running the Unit Tests

The test suite uses **pytest** with an in-memory SQLite database - no running server or seeded database required.

### Run all tests

```bash
python -m pytest tests/ -v
```

### Run a single test file

```bash
python -m pytest tests/test_sessions.py -v
```

### Run a single test by name

```bash
python -m pytest tests/ -v -k "test_login_success"
```

### Expected output

```
80 passed in ~30s
```

Each test gets its own isolated in-memory database seeded with:
- One user (`testuser` / `password123`)
- One vulnerability with a CTF challenge, one question, and one hint
- One CVE (`CVE-2021-99999`) linked to the vulnerability

The following is tested for every endpoint group:

| File | Endpoint(s) | Tests |
|---|---|---|
| `test_register.py` | `POST /api/register` | Success, validation errors, duplicate conflicts |
| `test_sessions.py` | `POST/DELETE /api/sessions` | Login, wrong credentials, logout, token revocation |
| `test_home.py` | `GET /api/home` | Dashboard shape, initial progress, auth guards |
| `test_vulnerabilities.py` | `GET/POST /api/vulnerabilities/…` | Description, questions, answer submission, completion tracking |
| `test_ctf.py` | `GET/POST /api/vulnerabilities/{id}/ctf` | Challenge retrieval, correct/wrong flags, completion state |
| `test_cve.py` | `GET /api/cve/{cveId}` | Lookup, related vulns, invalid CVE format, 404 |
| `test_account.py` | `GET/PUT/DELETE /api/account` | Profile, field updates, validation, duplicate checks, deletion |
