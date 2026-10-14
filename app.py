import hmac
import os
import re
import secrets
import warnings
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


def _csrf_token() -> str:
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _valid_csrf_token() -> bool:
    submitted = request.form.get("_csrf_token", "")
    expected = session.get("_csrf_token", "")
    return bool(submitted and expected and hmac.compare_digest(submitted, expected))


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.current_user is None:
            flash("Please log in to view your dashboard.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    is_production = os.environ.get("APP_ENV", "").lower() == "production"
    supplied_config = test_config or {}
    secret_key = os.environ.get("SECRET_KEY") or supplied_config.get("SECRET_KEY")

    if is_production and not secret_key:
        raise RuntimeError("Set a stable SECRET_KEY before running in production.")
    if not secret_key:
        secret_key = secrets.token_hex(32)
        warnings.warn(
            "SECRET_KEY is not set; sessions will be invalidated when the app restarts.",
            RuntimeWarning,
            stacklevel=2,
        )

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", "sqlite:///aliascard.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=is_production,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)

    @app.before_request
    def load_current_user() -> None:
        user_id = session.get("user_id")
        g.current_user = db.session.get(User, user_id) if isinstance(user_id, int) else None
        if user_id is not None and g.current_user is None:
            session.clear()

    @app.context_processor
    def inject_template_helpers() -> dict[str, Any]:
        return {
            "csrf_token": _csrf_token,
            "current_user": g.get("current_user"),
        }

    @app.get("/")
    def home():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            if not _valid_csrf_token():
                flash("Your session expired. Please try again.", "error")
                return redirect(url_for("register"))

            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not email or not password or not confirm_password:
                flash("Please complete every field.", "error")
            elif (
                len(email) > 254
                or re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is None
            ):
                flash("Enter a valid email address.", "error")
            elif len(password) < 12:
                flash("Choose a password with at least 12 characters.", "error")
            elif len(password) > 128:
                flash("Your password must be 128 characters or fewer.", "error")
            elif password != confirm_password:
                flash("Those passwords do not match.", "error")
            elif db.session.scalar(db.select(User.id).where(User.email == email)):
                flash("An account with that email already exists.", "error")
            else:
                user = User(email=email, password_hash=generate_password_hash(password))
                db.session.add(user)
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    flash("An account with that email already exists.", "error")
                else:
                    session.clear()
                    session["user_id"] = user.id
                    flash("Your AliasCard account is ready.", "success")
                    return redirect(url_for("dashboard"))

            return redirect(url_for("register"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.current_user is not None:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            if not _valid_csrf_token():
                flash("Your session expired. Please try again.", "error")
                return redirect(url_for("login"))

            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not email or not password:
                flash("Enter your email and password.", "error")
            elif len(password) > 128:
                flash("Your password must be 128 characters or fewer.", "error")
            else:
                user = db.session.scalar(
                    db.select(User).where(User.email == email)
                )
                if user is None or not check_password_hash(user.password_hash, password):
                    flash("The email or password you entered is incorrect.", "error")
                else:
                    session.clear()
                    session["user_id"] = user.id
                    flash("Welcome back.", "success")
                    return redirect(url_for("dashboard"))

            return redirect(url_for("login"))

        return render_template("login.html")

    @app.post("/logout")
    def logout():
        if not _valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("home"))

        session.clear()
        flash("You have been securely logged out.", "success")
        return redirect(url_for("home"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=g.current_user)

    @app.get("/virtual-cards")
    @login_required
    def virtual_cards():
        return redirect(url_for("dashboard", _anchor="your-cards"))

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
