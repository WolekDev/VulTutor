import os
from flask import Flask, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_swagger_ui import get_swaggerui_blueprint
from config import Config

db = SQLAlchemy()
jwt = JWTManager()

# In-memory set of revoked token JTIs (for logout / session invalidation)
token_blocklist: set[str] = set()


def create_app(config_class: type = Config) -> Flask:
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    app.config.from_object(config_class)

    db.init_app(app)
    jwt.init_app(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):  # noqa: ARG001
        return jwt_payload["jti"] in token_blocklist

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):  # noqa: ARG001
        return jsonify({"code": 401, "message": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(reason):  # noqa: ARG001
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(reason):  # noqa: ARG001
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):  # noqa: ARG001
        return jsonify({"code": 401, "message": "Token has been revoked"}), 401

    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    from app.frontend import frontend_bp
    app.register_blueprint(frontend_bp)

    # Swagger UI at /docs — reads the spec from /api/openapi.yaml
    swagger_bp = get_swaggerui_blueprint(
        "/docs",
        "/api/openapi.yaml",
        config={"app_name": "VulTutor API"},
    )
    app.register_blueprint(swagger_bp)

    # Serve the OpenAPI spec file
    spec_dir = os.path.join(app.root_path, "..")

    @app.route("/api/openapi.yaml")
    def openapi_spec():
        return send_from_directory(spec_dir, "openapi.yaml", mimetype="application/yaml")

    with app.app_context():
        db.create_all()

    return app
