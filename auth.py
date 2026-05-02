import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from models import get_user_by_id


ALGORITHM = "HS256"
TOKEN_BLACKLIST = set()
TOKEN_LIFETIME = timedelta(hours=1)


def log_security_attempt(endpoint, reason, username="unknown"):
    username = username or "unknown"
    logging.getLogger("security").warning(
        "endpoint=%s | reason=%s | username=%s", endpoint, reason, username
    )


def get_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()

    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]

    return None


def get_username_without_verifying(token):
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("username", "unknown")
    except jwt.InvalidTokenError:
        return "unknown"


def create_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + TOKEN_LIFETIME,
    }

    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm=ALGORITHM)


def blacklist_token(token):
    TOKEN_BLACKLIST.add(token)


def token_required(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()

        if not token:
            log_security_attempt(request.path, "Missing or malformed bearer token")
            return jsonify({"error": "Authorization token is required."}), 401

        if token in TOKEN_BLACKLIST:
            username = get_username_without_verifying(token)
            log_security_attempt(request.path, "Blacklisted token", username)
            return jsonify({"error": "Token has been logged out."}), 401

        try:
            payload = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithms=[ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            username = get_username_without_verifying(token)
            log_security_attempt(request.path, "Expired token", username)
            return jsonify({"error": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            log_security_attempt(request.path, "Invalid or tampered token")
            return jsonify({"error": "Invalid token."}), 401

        user = get_user_by_id(payload.get("user_id"))
        if not user:
            log_security_attempt(
                request.path, "Token user no longer exists", payload.get("username")
            )
            return jsonify({"error": "Invalid token user."}), 401

        g.current_user = {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }
        g.current_token = token

        return view_function(*args, **kwargs)

    return wrapper


def admin_required(view_function):
    @wraps(view_function)
    @token_required
    def wrapper(*args, **kwargs):
        if g.current_user["role"] != "admin":
            log_security_attempt(
                request.path, "Forbidden: admin role required", g.current_user["username"]
            )
            return jsonify({"error": "Admin access required."}), 403

        return view_function(*args, **kwargs)

    return wrapper
