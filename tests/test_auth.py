import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app import User, WalletCheckout, WalletTopUp, create_app, db
from werkzeug.security import check_password_hash


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "STRIPE_SECRET_KEY": "sk_test_aliascard",
                "STRIPE_PUBLISHABLE_KEY": "pk_test_aliascard",
                "STRIPE_WEBHOOK_SECRET": "whsec_aliascard",
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

    def csrf_token(self, endpoint):
        response = self.client.get(endpoint)
        self.assertEqual(response.status_code, 200)
        match = re.search(
            r'name="_csrf_token"\s+value="([^"]+)"',
            response.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def assert_no_arrow_indicators(self, response):
        html = response.get_data(as_text=True)
        arrows = (
            "→", "←", "↗", "↘", "↖", "↙", "↓", "↑", "➜", "➝", "⟶", "⟵", "⮕"
        )
        for arrow in arrows:
            with self.subTest(arrow=arrow):
                self.assertNotIn(arrow, html)
        self.assertNotIn("profile-chevron", html)

    def register(self, email="person@example.com", password="secure-password-123"):
        token = self.csrf_token("/register")
        return self.client.post(
            "/register",
            data={
                "_csrf_token": token,
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )

    def log_out(self):
        token = self.csrf_token("/dashboard")
        return self.client.post(
            "/logout",
            data={"_csrf_token": token},
            follow_redirects=True,
        )

    def test_register_hashes_password_and_logs_user_in(self):
        response = self.register()
        self.assertIn(b"Your AliasCard account is ready.", response.data)
        self.assertIn(b"person@example.com", response.data)

        with self.app.app_context():
            user = db.session.scalar(
                db.select(User).where(User.email == "person@example.com")
            )
            self.assertIsNotNone(user)
            self.assertNotEqual(user.password_hash, "secure-password-123")
            self.assertTrue(
                check_password_hash(user.password_hash, "secure-password-123")
            )
            self.assertIsNotNone(user.created_at)

    def test_duplicate_email_is_rejected_case_insensitively(self):
        self.register()
        self.log_out()

        response = self.register(email="PERSON@example.com")
        self.assertIn(b"An account with that email already exists.", response.data)
        with self.app.app_context():
            self.assertEqual(db.session.scalar(db.select(db.func.count(User.id))), 1)

    def test_invalid_password_confirmation_is_rejected(self):
        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={
                "_csrf_token": token,
                "email": "person@example.com",
                "password": "secure-password-123",
                "confirm_password": "another-password-123",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Those passwords do not match.", response.data)

    def test_empty_registration_fields_are_rejected(self):
        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={
                "_csrf_token": token,
                "email": "",
                "password": "",
                "confirm_password": "",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Please complete every field.", response.data)

    def test_login_rejects_invalid_credentials_and_accepts_valid_credentials(self):
        self.register()
        self.log_out()

        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={
                "_csrf_token": token,
                "email": "person@example.com",
                "password": "incorrect-password",
            },
            follow_redirects=True,
        )
        self.assertIn(
            b"The email or password you entered is incorrect.", response.data
        )

        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={
                "_csrf_token": token,
                "email": "PERSON@example.com",
                "password": "secure-password-123",
            },
            follow_redirects=True,
        )
        self.assertIn(b"person@example.com", response.data)
        self.assertIn(b"Your card space is ready.", response.data)
        self.assertIn(b"Issuing setup required", response.data)

    def test_dashboard_shows_account_overview_and_card_issuing_status(self):
        self.register()

        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your virtual cards", response.data)
        self.assertIn(b"Recent activity", response.data)
        self.assertIn(b"Account security", response.data)
        self.assertIn(b"Card issuing isn", response.data)
        self.assert_no_arrow_indicators(response)

    def test_successful_login_redirects_directly_to_dashboard(self):
        self.register()
        self.log_out()

        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={
                "_csrf_token": token,
                "email": "person@example.com",
                "password": "secure-password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_authenticated_user_visiting_login_is_redirected_to_dashboard(self):
        self.register()

        response = self.client.get("/login")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_dashboard_requires_login_and_logout_clears_session(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

        self.register()
        response = self.log_out()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"You have been securely logged out.", response.data)

        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_virtual_cards_redirects_signed_out_user_to_login(self):
        response = self.client.get("/virtual-cards")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_virtual_cards_redirects_signed_in_user_to_dashboard_cards(self):
        self.register()

        response = self.client.get("/virtual-cards")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard#your-cards")

    def test_home_virtual_card_options_use_protected_route(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.count(b'href="/virtual-cards"'), 2)
        self.assertNotIn(b"Secure payments for you and your AI agents", response.data)
        self.assertIn(b"Privacy is crucial", response.data)
        self.assertNotIn(b">Pricing</a>", response.data)
        self.assertEqual(response.data.count(b"nav-dropdown-toggle"), 3)
        self.assertEqual(response.data.count(b'class="chevron"'), 3)
        self.assertEqual(response.data.count(b'class="dropdown-panel'), 3)
        self.assert_no_arrow_indicators(response)

    def test_auth_pages_have_no_arrow_indicators(self):
        for endpoint in ("/login", "/register"):
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 200)
                self.assert_no_arrow_indicators(response)

    def test_wallet_requires_login(self):
        response = self.client.get("/wallet")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_wallet_renders_zar_balance_top_up_methods_and_workspace_link(self):
        self.register()

        response = self.client.get("/wallet")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ZAR 0.00", response.data)
        self.assertIn(b"Apple Pay", response.data)
        self.assertIn(b"Google Pay", response.data)
        self.assertIn(b"Credit or debit card", response.data)
        self.assert_no_arrow_indicators(response)
        dashboard = self.client.get("/dashboard")
        self.assertIn(b'href="/wallet"', dashboard.data)

    def test_wallet_top_up_creates_stripe_checkout_without_crediting_balance(self):
        self.register()
        checkout = SimpleNamespace(
            id="cs_test_aliascard",
            client_secret="cs_test_aliascard_secret_test",
        )
        with patch("app.stripe.StripeClient") as client_factory:
            stripe_client = client_factory.return_value
            stripe_client.v1.checkout.sessions.create.return_value = checkout
            token = self.csrf_token("/wallet")
            response = self.client.post(
                "/wallet/top-up",
                data={"_csrf_token": token, "amount": "250.00"},
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], "/wallet/checkout")
        client_factory.assert_called_once_with("sk_test_aliascard")
        checkout_args = stripe_client.v1.checkout.sessions.create.call_args.args[0]
        self.assertEqual(checkout_args["ui_mode"], "embedded")
        self.assertEqual(checkout_args["payment_method_types"], ["card"])
        self.assertIn("{CHECKOUT_SESSION_ID}", checkout_args["return_url"])
        self.assertEqual(checkout_args["line_items"][0]["price_data"]["currency"], "zar")
        self.assertEqual(checkout_args["line_items"][0]["price_data"]["unit_amount"], 25000)
        with self.app.app_context():
            top_up = db.session.scalar(db.select(WalletTopUp))
            self.assertEqual(top_up.status, "pending")
            self.assertEqual(top_up.amount_minor, 25000)
            checkout_record = db.session.get(WalletCheckout, top_up.id)
            self.assertEqual(
                checkout_record.client_secret,
                "cs_test_aliascard_secret_test",
            )
        with self.client.session_transaction() as session:
            self.assertNotIn("wallet_checkout_client_secret", session)

        checkout_page = self.client.get("/wallet/checkout")
        self.assertEqual(checkout_page.status_code, 200)
        self.assertIn(b"Secure checkout", checkout_page.data)
        self.assertIn(b"Stripe(", checkout_page.data)
        self.assertIn(b"initEmbeddedCheckout", checkout_page.data)
        self.assertIn(b"pk_test_aliascard", checkout_page.data)
        self.assertIn(b"cs_test_aliascard_secret_test", checkout_page.data)
        self.assert_no_arrow_indicators(checkout_page)

        wallet = self.client.get("/wallet")
        self.assertIn(b"ZAR 0.00", wallet.data)

    def test_wallet_checkout_requires_login_and_valid_pending_top_up(self):
        response = self.client.get("/wallet/checkout")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

        self.register()
        response = self.client.get("/wallet/checkout", follow_redirects=True)
        self.assertIn(b"Start a wallet top-up to open checkout.", response.data)

    def test_wallet_checkout_return_does_not_credit_payment_without_webhook(self):
        self.register()
        checkout = SimpleNamespace(
            id="cs_test_aliascard",
            client_secret="cs_test_aliascard_secret_test",
        )
        with patch("app.stripe.StripeClient") as client_factory:
            client_factory.return_value.v1.checkout.sessions.create.return_value = checkout
            token = self.csrf_token("/wallet")
            self.client.post(
                "/wallet/top-up",
                data={"_csrf_token": token, "amount": "250.00"},
            )

        response = self.client.get(
            "/wallet/checkout-return?session_id=cs_test_aliascard",
            follow_redirects=True,
        )
        self.assertIn(
            b"Your balance will update once Stripe confirms the payment.",
            response.data,
        )
        self.assertIn(b"ZAR 0.00", response.data)

    def test_wallet_rejects_top_ups_outside_configured_amount_limits(self):
        self.register()

        for amount in ("9.99", "10000.01", "1e3", "10.001"):
            with self.subTest(amount=amount):
                token = self.csrf_token("/wallet")
                response = self.client.post(
                    "/wallet/top-up",
                    data={"_csrf_token": token, "amount": amount},
                    follow_redirects=True,
                )
                self.assertIn(b"Enter a top-up between R10.00 and R10,000.00.", response.data)
        with self.app.app_context():
            self.assertEqual(
                db.session.scalar(db.select(db.func.count(WalletTopUp.id))), 0
            )

    def test_wallet_top_ups_stay_disabled_without_webhook_signing_secret(self):
        self.register()
        self.app.config["STRIPE_WEBHOOK_SECRET"] = ""

        wallet = self.client.get("/wallet")
        self.assertIn(b"Secure checkout is being set up.", wallet.data)

        token = self.csrf_token("/wallet")
        response = self.client.post(
            "/wallet/top-up",
            data={"_csrf_token": token, "amount": "250.00"},
            follow_redirects=True,
        )
        self.assertIn(b"Wallet top-ups are not available yet.", response.data)
        with self.app.app_context():
            self.assertEqual(
                db.session.scalar(db.select(db.func.count(WalletTopUp.id))), 0
            )

    def test_wallet_top_ups_stay_disabled_without_publishable_key(self):
        self.register()
        self.app.config["STRIPE_PUBLISHABLE_KEY"] = ""

        wallet = self.client.get("/wallet")
        self.assertIn(b"Secure checkout is being set up.", wallet.data)

        token = self.csrf_token("/wallet")
        response = self.client.post(
            "/wallet/top-up",
            data={"_csrf_token": token, "amount": "250.00"},
            follow_redirects=True,
        )
        self.assertIn(b"Wallet top-ups are not available yet.", response.data)

    def test_invalid_stripe_webhook_signature_is_rejected(self):
        response = self.client.post(
            "/stripe/webhook",
            data=b"{}",
            headers={"Stripe-Signature": "invalid"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_signed_paid_webhook_credits_wallet_once(self):
        self.register()
        checkout = SimpleNamespace(
            id="cs_test_aliascard",
            client_secret="cs_test_aliascard_secret_test",
        )
        with patch("app.stripe.StripeClient") as client_factory:
            client_factory.return_value.v1.checkout.sessions.create.return_value = checkout
            token = self.csrf_token("/wallet")
            self.client.post(
                "/wallet/top-up",
                data={"_csrf_token": token, "amount": "250.00"},
            )

        with self.app.app_context():
            top_up = db.session.scalar(db.select(WalletTopUp))
            event = SimpleNamespace(
                type="checkout.session.completed",
                data=SimpleNamespace(
                    object=SimpleNamespace(
                        id=checkout.id,
                        payment_status="paid",
                        metadata={"wallet_top_up_id": str(top_up.id)},
                        client_reference_id=str(top_up.user_id),
                        amount_total=25000,
                        currency="zar",
                        payment_intent="pi_test_aliascard",
                    )
                ),
            )

        with patch("app.stripe.Webhook.construct_event", return_value=event):
            response = self.client.post(
                "/stripe/webhook",
                data=b"{}",
                headers={"Stripe-Signature": "test-signature"},
                content_type="application/json",
            )
            duplicate_response = self.client.post(
                "/stripe/webhook",
                data=b"{}",
                headers={"Stripe-Signature": "test-signature"},
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(duplicate_response.status_code, 200)
        with self.app.app_context():
            top_up = db.session.scalar(db.select(WalletTopUp))
            self.assertEqual(top_up.status, "credited")
            self.assertEqual(top_up.stripe_payment_intent_id, "pi_test_aliascard")
            self.assertIsNone(db.session.get(WalletCheckout, top_up.id))
            credited_total = db.session.scalar(
                db.select(db.func.sum(WalletTopUp.amount_minor)).where(
                    WalletTopUp.status == "credited"
                )
            )
            self.assertEqual(credited_total, 25000)
        wallet = self.client.get("/wallet")
        self.assertIn(b"ZAR 250.00", wallet.data)

    def test_webhook_does_not_credit_mismatched_payment(self):
        self.register()
        checkout = SimpleNamespace(
            id="cs_test_aliascard",
            client_secret="cs_test_aliascard_secret_test",
        )
        with patch("app.stripe.StripeClient") as client_factory:
            client_factory.return_value.v1.checkout.sessions.create.return_value = checkout
            token = self.csrf_token("/wallet")
            self.client.post(
                "/wallet/top-up",
                data={"_csrf_token": token, "amount": "250.00"},
            )

        with self.app.app_context():
            top_up = db.session.scalar(db.select(WalletTopUp))
            event = SimpleNamespace(
                type="checkout.session.completed",
                data=SimpleNamespace(
                    object=SimpleNamespace(
                        id=checkout.id,
                        payment_status="paid",
                        metadata={"wallet_top_up_id": str(top_up.id)},
                        client_reference_id=str(top_up.user_id),
                        amount_total=10000,
                        currency="zar",
                        payment_intent="pi_test_aliascard",
                    )
                ),
            )
        with patch("app.stripe.Webhook.construct_event", return_value=event):
            response = self.client.post(
                "/stripe/webhook",
                data=b"{}",
                headers={"Stripe-Signature": "test-signature"},
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            top_up = db.session.scalar(db.select(WalletTopUp))
            self.assertEqual(top_up.status, "pending")

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post(
            "/register",
            data={
                "email": "person@example.com",
                "password": "secure-password-123",
                "confirm_password": "secure-password-123",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Your session expired. Please try again.", response.data)
        with self.app.app_context():
            self.assertEqual(db.session.scalar(db.select(db.func.count(User.id))), 0)


if __name__ == "__main__":
    unittest.main()
