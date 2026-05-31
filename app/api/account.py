from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from marshmallow import ValidationError
from werkzeug.security import generate_password_hash

from app import db
from app.api import api_bp
from app.models import Account
from app.validators import AccountUpdateSchema

_update_schema = AccountUpdateSchema()


def _require_user():
    """Return (Account, None) or (None, error_response)."""
    try:
        verify_jwt_in_request()
        user_id = int(get_jwt_identity())
        user = db.session.get(Account, user_id)
        if not user:
            raise ValueError("user not found")
        return user, None
    except Exception:
        return None, (jsonify({"code": 401, "message": "Unauthorized"}), 401)


@api_bp.route("/account", methods=["GET"])
def get_account():
    user, err = _require_user()
    if err:
        return err
    return jsonify({"userId": user.userId, "username": user.username, "email": user.email}), 200


@api_bp.route("/account", methods=["PUT"])
def update_account():
    user, err = _require_user()
    if err:
        return err

    if not request.is_json:
        return jsonify({"code": 400, "message": "Request body must be JSON"}), 400

    try:
        data = _update_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify({"code": 400, "message": exc.messages}), 400

    if data.get("username"):
        conflict = Account.query.filter_by(username=data["username"]).first()
        if conflict and conflict.userId != user.userId:
            return jsonify({"code": 409, "message": "Username already taken"}), 409
        user.username = data["username"]

    if data.get("email"):
        conflict = Account.query.filter_by(email=data["email"]).first()
        if conflict and conflict.userId != user.userId:
            return jsonify({"code": 409, "message": "Email already in use"}), 409
        user.email = data["email"]

    if data.get("password"):
        user.passwordHash = generate_password_hash(data["password"])

    db.session.commit()
    return jsonify({"userId": user.userId, "username": user.username, "email": user.email}), 200


@api_bp.route("/account", methods=["DELETE"])
def delete_account():
    user, err = _require_user()
    if err:
        return err
    db.session.delete(user)
    db.session.commit()
    return "", 204
