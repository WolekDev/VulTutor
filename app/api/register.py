from flask import request, jsonify
from flask_jwt_extended import create_access_token
from marshmallow import ValidationError
from werkzeug.security import generate_password_hash

from app import db
from app.api import api_bp
from app.models import Account
from app.validators import RegisterSchema

_register_schema = RegisterSchema()


@api_bp.route("/register", methods=["POST"])
def register():
    if not request.is_json:
        return jsonify({"code": 400, "message": "Request body must be JSON"}), 400

    try:
        data = _register_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify({"code": 400, "message": exc.messages}), 400

    if Account.query.filter_by(username=data["username"]).first():
        return jsonify({"code": 409, "message": "Username already exists"}), 409

    if Account.query.filter_by(email=data["email"]).first():
        return jsonify({"code": 409, "message": "Email already in use"}), 409

    user = Account(
        username=data["username"],
        email=data["email"],
        passwordHash=generate_password_hash(data["password"]),
    )
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.userId))
    return jsonify({"token": token, "expiresIn": 3600}), 201
