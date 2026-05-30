from flask import Blueprint

api_bp = Blueprint("api", __name__)

from app.api import sessions, register, home, vulnerabilities, cve, account  # noqa: E402, F401
