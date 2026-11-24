# Deployment Documentation

## Production architecture

```text
Internet
   |
TLS reverse proxy (nginx / cloud load balancer)
   |
Gunicorn (web)  ────── PostgreSQL 16
   |                   Redis 7
Celery workers ────────┘
```

## Prerequisites

- Python 3.12 (or Docker + Docker Compose)
- PostgreSQL 14+
- Redis 6+
- OSV.dev network access; optional NVD API key
- Optional binaries: `pip-audit`, `gitleaks`

## Environment configuration

Copy `.env.example` to `.env` and set at minimum:

| Variable | Purpose |
|---|---|
| `DJANGO_SECRET_KEY` | Long random signing key. |
| `DJANGO_DEBUG` | Must be `False` in production. |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated hostnames. |
| `DATABASE_URL` | `postgresql://user:password@host:5432/dbname`. |
| `CELERY_BROKER_URL` | Redis broker URL. |
| `CELERY_RESULT_BACKEND` | Redis result backend URL. |
| `SECURE_SSL_REDIRECT` | `True` behind TLS termination. |
| `SESSION_COOKIE_SECURE` | `True` for HTTPS-only cookies. |
| `CSRF_COOKIE_SECURE` | `True` for HTTPS-only CSRF cookies. |
| `SECURE_HSTS_SECONDS` | Start with `31536000` once TLS is verified. |
| `NVD_API_KEY` | Optional; increases NVD rate limit. |
| `AI_PROVIDER` | `rule_engine` (default) or `openai`. |
| `OPENAI_API_KEY` | Required only when `AI_PROVIDER=openai`. |

## Docker Compose deployment

```powershell
copy .env.example .env
docker compose up --build -d
docker compose exec web python manage.py createsuperuser
```

The `web` service applies migrations at startup. The `worker` service consumes `celery`, `scans` and `maintenance` queues. Volumes persist PostgreSQL data, static files and uploads/reports.

## Manual deployment

```powershell
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120
celery -A config worker -l info -Q celery,scans,maintenance --concurrency=2
```

Serve `/static/` and `/media/` through your reverse proxy or object storage. WhiteNoise is configured for static assets.

## Database

Production uses PostgreSQL by default. Create the database and user:

```sql
CREATE USER supplychainx WITH PASSWORD 'replace-me';
CREATE DATABASE supplychainx OWNER supplychainx;
```

Migrations are managed by Django; no manual schema changes are required.

## Background scanning

- Celery is the primary execution path.
- If Redis is unreachable, the application falls back to a daemon thread so scans still complete on single-node deployments.
- For high-volume deployments, scale only the `worker` service and keep the `scans` queue dedicated.

## Optional security tools

Install binaries into the worker image/container:

```powershell
pip install pip-audit
# install gitleaks from https://github.com/gitleaks/gitleaks/releases
```

Then enable:

```env
ENABLE_PIP_AUDIT=True
ENABLE_GITLEAKS=True
```

Tool availability and results are recorded per scan in `sources.source_status`. Disabled or missing tools are reported as warnings, never as findings.

## TLS and headers

The middleware sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and COOP. HSTS and secure cookies are enabled through the environment variables above. Verify with:

```powershell
curl -I https://your-host/
```

## Backups

Back up:

1. PostgreSQL database (`pg_dump`).
2. `media/archives/` for reproducible scans.
3. `media/reports/` for generated PDF/CSV/SBOM artefacts.

## Upgrade procedure

1. Take a database and media backup.
2. Deploy new image/code.
3. Run `python manage.py migrate --noinput`.
4. Run `python manage.py collectstatic --noinput`.
5. Restart web and worker processes.
6. Run `python manage.py check --deploy`.

## Health verification

```powershell
python manage.py check --deploy
python manage.py test tests
curl -H "Authorization: Token <token>" http://your-host/api/intel-sources/
```

The intel-sources endpoint shows live status for OSV, NVD and optional tools.
