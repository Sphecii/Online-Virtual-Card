# AliasCard

AliasCard is a Flask application with a SQLite-backed account flow. It includes
email registration, password hashing, CSRF-protected forms, login/logout, and a
protected account dashboard. Virtual card creation is not connected yet.

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

4. Start the app:

   ```powershell
   python app.py
   ```

The SQLite database is created automatically at `instance/aliascard.db` the
first time the app starts. To use another SQLAlchemy database URL, set
`DATABASE_URL` in `.env`.

Open `http://127.0.0.1:5000`, then use **Sign up** to create an account. New
accounts require a valid email address and a password of at least 12 characters.

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
