# SecureShield

SecureShield is a small Flask API that demonstrates JWT authentication, role-based access control, logout token blacklisting, and security logging for rejected requests.

## Features

- User registration with bcrypt password hashing
- JWT login with one-hour token expiry
- Protected profile endpoint
- Admin-only user deletion endpoint
- Logout flow with in-memory token blacklist
- Browser console for testing the API flows

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and replace `SECRET_KEY` with a long random value before running the app.

## Run

```powershell
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## API Endpoints

| Method | Path | Access |
| --- | --- | --- |
| GET | `/api/status` | Public |
| POST | `/register` | Public |
| POST | `/login` | Public |
| GET | `/profile` | Authenticated |
| DELETE | `/user/<id>` | Admin |
| POST | `/logout` | Authenticated |

## Notes

- This is an educational demo for RBAC and JWT security flows. The registration screen allows selecting roles so the admin and user scenarios can be tested quickly.
- `secure_shield.db` is created automatically at runtime.
- `security.log` is created automatically when rejected requests are logged.
- Local runtime files, cache folders, and secrets are ignored by git.
