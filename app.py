import hmac
import logging
import os
import re
import secrets
import warnings
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
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
import stripe
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

db = SQLAlchemy()
logger = logging.getLogger(__name__)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class WalletTopUp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount_minor = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default="zar")
    status = db.Column(db.String(16), nullable=False, default="pending")
    stripe_checkout_session_id = db.Column(db.String(255), unique=True)
    stripe_payment_intent_id = db.Column(db.String(255), unique=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    credited_at = db.Column(db.DateTime(timezone=True))


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
        STRIPE_SECRET_KEY=os.environ.get("STRIPE_SECRET_KEY", ""),
        STRIPE_WEBHOOK_SECRET=os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
        WALLET_CURRENCY="zar",
        WALLET_MIN_TOP_UP_MINOR=1000,
        WALLET_MAX_TOP_UP_MINOR=1_000_000,
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

    @app.get("/wallet")
    @login_required
    def wallet():
        if request.args.get("checkout") == "success":
            flash(
                "Checkout completed. Your balance will update once Stripe confirms the payment.",
                "info",
            )
        elif request.args.get("checkout") == "cancelled":
            flash("Your top-up was cancelled; no money was added.", "info")

        balance_minor = db.session.scalar(
            db.select(db.func.coalesce(db.func.sum(WalletTopUp.amount_minor), 0)).where(
                WalletTopUp.user_id == g.current_user.id,
                WalletTopUp.status == "credited",
            )
        )
        top_ups = db.session.scalars(
            db.select(WalletTopUp)
            .where(WalletTopUp.user_id == g.current_user.id)
            .order_by(WalletTopUp.created_at.desc())
            .limit(20)
        ).all()
        return render_template(
            "wallet.html",
            user=g.current_user,
            balance=format(Decimal(balance_minor) / Decimal(100), ",.2f"),
            currency=app.config["WALLET_CURRENCY"].upper(),
            top_ups=top_ups,
            stripe_configured=bool(
                app.config["STRIPE_SECRET_KEY"]
                and app.config["STRIPE_WEBHOOK_SECRET"]
            ),
        )

    @app.post("/wallet/top-up")
    @login_required
    def create_wallet_top_up():
        if not _valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("wallet"))

        amount_text = request.form.get("amount", "").strip()
        if re.fullmatch(r"\d{1,5}(?:\.\d{1,2})?", amount_text) is None:
            flash("Enter a top-up between R10.00 and R10,000.00.", "error")
            return redirect(url_for("wallet"))
        try:
            amount = Decimal(amount_text)
            amount_minor = int(amount * 100)
        except (InvalidOperation, ValueError):
            flash("Enter a valid top-up amount.", "error")
            return redirect(url_for("wallet"))

        if (
            not app.config["WALLET_MIN_TOP_UP_MINOR"] <= amount_minor
            <= app.config["WALLET_MAX_TOP_UP_MINOR"]
        ):
            flash("Enter a top-up between R10.00 and R10,000.00.", "error")
            return redirect(url_for("wallet"))
        if not (
            app.config["STRIPE_SECRET_KEY"]
            and app.config["STRIPE_WEBHOOK_SECRET"]
        ):
            flash(
                "Wallet top-ups are not available yet. Please try again later.",
                "error",
            )
            return redirect(url_for("wallet"))

        top_up = WalletTopUp(
            user_id=g.current_user.id,
            amount_minor=amount_minor,
            currency=app.config["WALLET_CURRENCY"],
        )
        db.session.add(top_up)
        db.session.commit()

        try:
            stripe_client = stripe.StripeClient(app.config["STRIPE_SECRET_KEY"])
            checkout_session = stripe_client.v1.checkout.sessions.create(
                {
                    "mode": "payment",
                    "payment_method_types": ["card"],
                    "line_items": [
                        {
                            "price_data": {
                                "currency": top_up.currency,
                                "product_data": {"name": "AliasCard wallet top-up"},
                                "unit_amount": top_up.amount_minor,
                            },
                            "quantity": 1,
                        }
                    ],
                    "customer_email": g.current_user.email,
                    "client_reference_id": str(g.current_user.id),
                    "metadata": {"wallet_top_up_id": str(top_up.id)},
                    "success_url": url_for(
                        "wallet",
                        checkout="success",
                        _external=True,
                    )
                    + "&session_id={CHECKOUT_SESSION_ID}",
                    "cancel_url": url_for(
                        "wallet",
                        checkout="cancelled",
                        _external=True,
                    ),
                }
            )
        except stripe.StripeError:
            db.session.delete(top_up)
            db.session.commit()
            logger.exception("Stripe could not create the wallet top-up checkout.")
            flash("We couldn’t start checkout. Please try again.", "error")
            return redirect(url_for("wallet"))

        top_up.stripe_checkout_session_id = checkout_session.id
        db.session.commit()
        return redirect(checkout_session.url, code=303)

    @app.post("/stripe/webhook")
    def stripe_webhook():
        webhook_secret = app.config["STRIPE_WEBHOOK_SECRET"]
        if not webhook_secret:
            logger.error("Stripe webhook received without a configured signing secret.")
            return "", 503

        try:
            event = stripe.Webhook.construct_event(
                request.get_data(),
                request.headers.get("Stripe-Signature", ""),
                webhook_secret,
            )
        except (ValueError, stripe.SignatureVerificationError):
            logger.warning("Rejected an invalid Stripe webhook.")
            return "", 400

        paid_event_types = {
            "checkout.session.completed",
            "checkout.session.async_payment_succeeded",
        }
        failed_event_types = {
            "checkout.session.async_payment_failed",
            "checkout.session.expired",
        }
        if event.type not in paid_event_types | failed_event_types:
            return "", 200

        checkout = event.data.object
        if event.type in paid_event_types and checkout.payment_status != "paid":
            return "", 200

        metadata = checkout.metadata or {}
        top_up_id = metadata.get("wallet_top_up_id")
        try:
            top_up_id = int(top_up_id)
        except (TypeError, ValueError):
            top_up_id = None
        top_up = db.session.get(WalletTopUp, top_up_id) if top_up_id else None
        if (
            top_up is None
            or top_up.stripe_checkout_session_id != checkout.id
            or str(top_up.user_id) != str(checkout.client_reference_id)
            or top_up.amount_minor != checkout.amount_total
            or top_up.currency != checkout.currency
        ):
            logger.error("Stripe wallet payment did not match a pending top-up.")
            return "", 400

        if event.type in failed_event_types:
            if top_up.status == "pending":
                top_up.status = "failed"
                db.session.commit()
            return "", 200

        if top_up.status != "credited":
            top_up.status = "credited"
            top_up.credited_at = datetime.now(timezone.utc)
            if checkout.payment_intent:
                top_up.stripe_payment_intent_id = checkout.payment_intent
            db.session.commit()
        return "", 200

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
