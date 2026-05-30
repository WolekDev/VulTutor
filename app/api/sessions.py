from flask import request, jsonify
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    verify_jwt_in_request,
)
from marshmallow import ValidationError
from werkzeug.security import check_password_hash

from app import token_blocklist
from app.api import api_bp
from app.models import Account
from app.validators import LoginSchema

_login_schema = LoginSchema()


@api_bp.route("/sessions", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"code": 400, "message": "Request body must be JSON"}), 400

    try:
        data = _login_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify({"code": 400, "message": exc.messages}), 400

    user = Account.query.filter_by(username=data["username"]).first()
    if not user or not check_password_hash(user.passwordHash, data["password"]):
        return jsonify({"code": 401, "message": "Invalid username or password"}), 401

    token = create_access_token(identity=str(user.userId))
    return jsonify({"token": token, "expiresIn": 3600}), 201


@api_bp.route("/sessions", methods=["DELETE"])
def logout():
    try:
        verify_jwt_in_request()
    except Exception:
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    jti = get_jwt()["jti"]
    token_blocklist.add(jti)
    return "", 204
