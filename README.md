# PhishGuard Backend

PhishGuard is a Django REST API for URL phishing analysis, scan logging, and
whitelist management.

## Local development

The supported development baseline is Python 3.13.15 and Django 5.2.17 LTS.

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

The API is available at `http://127.0.0.1:8000/api/`.

## Configuration

Local configuration belongs in `.env`, which Git ignores. Copy
`.env.example` to get safe development defaults. Hosted environments must set
their own `DJANGO_SECRET_KEY`, allowed hosts, CORS origins, database URL, and
HTTPS security options.

Never commit `.env`, `db.sqlite3`, user scan data, or generated cache files.

## Detection engine

The URL API currently defaults to the explainable rules engine. The historical
CNN can be loaded through the lightweight NumPy adapter, but it is intentionally
disabled because the repository contains no training/evaluation provenance and
smoke evaluation shows unacceptable false positives. See
`ml_models/MODEL_CARD.md` before changing `PHISHGUARD_ML_ENABLED`.

## Verification

```bash
python -m pip check
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
```
