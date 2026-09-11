# Contributing

Create a focused branch from the latest reviewed baseline. Do not push feature
work directly to `main`.

## Development checks

Install development dependencies and enable the local checks:

```bash
python -m pip install -r requirements-dev.txt
pre-commit install
```

Before requesting review, run:

```bash
ruff check .
ruff format --check .
python manage.py check
python manage.py makemigrations --check --dry-run
coverage run manage.py test
coverage report
pip-audit --local --strict
python scripts/check_docs.py
```

Never commit secrets, local databases, generated caches, or personal scan data.
Explain security-sensitive behavior changes and include regression tests.
Update the architecture and threat model whenever a change adds a trust
boundary, external service, privileged operation, or persisted data field.
