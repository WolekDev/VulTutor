# VulTutor

VulTutor is a cybersecurity learning platform inspired by [WebGoat](https://owasp.org/www-project-webgoat/).
Users explore intentionally vulnerable exercises, quiz questions with hints, CTF (Capture The Flag) challenges,
and real-world CVE references — all in a safe, local environment.

---

## Tech Stack

| Layer      | Technology                               |
|------------|------------------------------------------|
| Backend    | Python · Flask · SQLAlchemy · SQLite     |
| Auth       | Flask-JWT-Extended (Bearer tokens)       |
| Validation | Marshmallow schemas                      |
| Frontend   | Flask (Jinja2 templates) · Bootstrap 5   |
| API Docs   | Swagger UI (flask-swagger-ui)            |

---

## Getting Started

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
2. To test protected endpoints, first call **POST /api/sessions** (or **POST /api/register**)
   with a username and password — the response contains a `token`.
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
└── static/                 # CSS and JS assets
```
