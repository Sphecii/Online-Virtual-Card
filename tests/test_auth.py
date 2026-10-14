import re
import unittest

from app import User, create_app, db
from werkzeug.security import check_password_hash


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
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
