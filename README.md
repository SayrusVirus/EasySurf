# EasySurf

EasySurf — локальный MVP GPT/PTC-платформы на FastAPI.

## Local development

From PowerShell:

```powershell
cd F:\EasySurf
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Open:

http://127.0.0.1:8000

## Production

Production deployment is configured through `render.yaml`.

The Render service uses:

- Root directory: `backend`
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check: `/`

## Required environment variables

The production environment must provide:

- `EASYSURF_PUBLIC_URL`
- `EASYSURF_SESSION_SECRET`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM`
- `SMTP_USE_TLS`

Secrets must be configured through the deployment platform and must not be committed to Git.

## Email verification

New registrations require email verification.

Verification links use a short-lived, one-time token. Only the token hash is stored in the database.

## Security

Before production use, review authentication, anti-fraud controls, rate limiting, payment/payout logic, database persistence and operational security.

Do not commit `.env` files or SQLite databases.
