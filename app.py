import os
import logging
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request
from flask_bcrypt import Bcrypt

from auth import (
    admin_required,
    blacklist_token,
    create_token,
    log_security_attempt,
    token_required,
)
from database import init_db
from models import create_user, delete_user, get_user_by_username


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

bcrypt = Bcrypt()


def configure_security_logging():
    """Write unauthorized and forbidden attempts to security.log."""
    log_path = BASE_DIR / "security.log"
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False

    if not any(
        isinstance(handler, logging.FileHandler)
        and Path(handler.baseFilename) == log_path
        for handler in security_logger.handlers
    ):
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
        security_logger.addHandler(handler)


def create_app():
    app = Flask(__name__)

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY is missing. Copy .env.example to .env and set a strong key."
        )

    app.config["SECRET_KEY"] = secret_key
    bcrypt.init_app(app)
    configure_security_logging()
    init_db()

    @app.route("/", methods=["GET"])
    def home():
        return render_template("index.html")

    @app.route("/api/status", methods=["GET"])
    def status():
        return jsonify(
            {
                "message": "SecureShield API is running.",
                "endpoints": {
                    "register": "POST /register",
                    "login": "POST /login",
                    "profile": "GET /profile",
                    "delete_user": "DELETE /user/<id>",
                    "logout": "POST /logout",
                },
            }
        )

    @app.route("/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        role = data.get("role", "user")

        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        if role not in ("user", "admin"):
            return jsonify({"error": "Role must be either 'user' or 'admin'."}), 400

        if get_user_by_username(username):
            return jsonify({"error": "Username already exists."}), 409

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user_id = create_user(username, password_hash, role)

        if user_id is None:
            return jsonify({"error": "Username already exists."}), 409

        return (
            jsonify(
                {
                    "message": "User registered successfully.",
                    "user": {"id": user_id, "username": username, "role": role},
                }
            ),
            201,
        )

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not username or not password:
            log_security_attempt("/login", "Missing username or password", username)
            return jsonify({"error": "Username and password are required."}), 400

        user = get_user_by_username(username)
        if not user or not bcrypt.check_password_hash(user["password_hash"], password):
            log_security_attempt("/login", "Invalid username or password", username)
            return jsonify({"error": "Invalid username or password."}), 401

        token = create_token(user)
        return jsonify({"message": "Login successful.", "token": token}), 200

    @app.route("/profile", methods=["GET"])
    @token_required
    def profile():
        return (
            jsonify(
                {
                    "message": "Profile access granted.",
                    "user": g.current_user,
                }
            ),
            200,
        )

    @app.route("/user/<int:user_id>", methods=["DELETE"])
    @admin_required
    def delete_user_route(user_id):
        if not delete_user(user_id):
            return jsonify({"error": "User not found."}), 404

        return jsonify({"message": f"User {user_id} deleted successfully."}), 200

    @app.route("/logout", methods=["POST"])
    @token_required
    def logout():
        blacklist_token(g.current_token)
        return jsonify({"message": "Logged out successfully."}), 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
