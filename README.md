# AliasCard

AliasCard is a Flask application with a SQLite-backed account flow. It includes
email registration, password hashing, CSRF-protected forms, login/logout, a
protected account dashboard, and a wallet with Stripe-hosted top-ups. Virtual
card creation is not connected yet.

## Setup

Python 3.10 or newer is required.

1. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and set `SECRET_KEY` to a unique random value.
   Generate one with:

   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. In the Stripe Dashboard, obtain a secret API key and configure a webhook for
   `checkout.session.completed` and `checkout.session.async_payment_succeeded`
   pointing to `https://your-domain/stripe/webhook`. Copy the API secret key to
   `STRIPE_SECRET_KEY` and the webhook signing secret to `STRIPE_WEBHOOK_SECRET`
   in `.env`. Use Stripe test keys and a local Stripe CLI webhook forwarder while
   developing. Never commit these values.

5. Start the app:

   ```powershell
   python app.py
   ```

The SQLite database is created automatically at `instance/aliascard.db` the
first time the app starts. To use another SQLAlchemy database URL, set
`DATABASE_URL` in `.env`.

Open `http://127.0.0.1:5000`, then use **Sign up** to create an account. New
accounts require a valid email address and a password of at least 12 characters.

## Wallet payments

The authenticated **Wallet** workspace accepts ZAR top-ups from R10.00 to
R10,000.00 through Stripe Checkout. Checkout accepts card payments and can show
Apple Pay or Google Pay when Stripe, the visitor's device/browser, and region
support them. Card details are collected by Stripe, not AliasCard.

The wallet balance changes only after the app verifies Stripe's webhook
signature and confirms the paid Checkout Session matches the user's pending
top-up, amount, and currency. A successful browser redirect is not treated as
payment confirmation. Configure HTTPS and the Stripe webhook before enabling
live payments; use Stripe test mode first.

## Production

Set `APP_ENV=production`, provide a persistent random `SECRET_KEY`, and set
`DATABASE_URL` to the production database. Production mode enables secure
session cookies and refuses to start without `SECRET_KEY`. Serve the app through
a production WSGI server over HTTPS; do not use Flask's development server in
production.

## Tests

Run the built-in test suite with:

```powershell
python -m unittest discover -s tests
```
