"""Django settings for SupplyChainX.

Defaults are production-oriented (PostgreSQL + strict security headers).
Local development can override via environment variables or a .env file.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY", "dev-only-insecure-key-change-me-before-deployment"
)
DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in {"1", "true", "yes"}
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
    if h.strip()
]

LOCAL_APPS = [
    "accounts",
    "organizations",
    "projects",
    "dependency_parser",
    "sbom_generator",
    "vulnerability_scanner",
    "cve_intelligence",
    "dependency_graph",
    "license_compliance",
    "ai_recommendations",
    "reports",
    "dashboard",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    *LOCAL_APPS,
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "config.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "dashboard.context_processors.platform_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# Database: PostgreSQL by default; SQLite is only for local/offline testing.
# ---------------------------------------------------------------------------
_database_url = os.environ.get("DATABASE_URL")
if _database_url:
    parsed = urlparse(_database_url)
    options = parse_qs(parsed.query)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": parsed.path.lstrip("/"),
            "USER": parsed.username or "",
            "PASSWORD": parsed.password or "",
            "HOST": parsed.hostname or "localhost",
            "PORT": str(parsed.port or 5432),
            "OPTIONS": {k: v[0] for k, v in options.items()},
        }
    }
else:
    engine = os.environ.get("DB_ENGINE", "django.db.backends.postgresql")
    if engine in {"sqlite", "sqlite3"}:
        engine = "django.db.backends.sqlite3"
    DATABASES = {
        "default": {
            "ENGINE": engine,
            "NAME": os.environ.get("DB_NAME", str(BASE_DIR / "db.sqlite3")),
            "USER": os.environ.get("DB_USER", "supplychainx"),
            "PASSWORD": os.environ.get("DB_PASSWORD", "supplychainx"),
            "HOST": os.environ.get("DB_HOST", "localhost"),
            "PORT": os.environ.get("DB_PORT", "5432"),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "dashboard:home"
LOGOUT_REDIRECT_URL = "accounts:login"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
        if not DEBUG
        else "whitenoise.storage.CompressedStaticFilesStorage"
    },
}

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
FILE_UPLOAD_MAX_MEMORY_SIZE = 4 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 32 * 1024 * 1024

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.UserRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"user": os.environ.get("API_RATE_LIMIT", "1000/hour")},
}

# ---------------------------------------------------------------------------
# SupplyChainX scanning configuration
# ---------------------------------------------------------------------------
SCAN_MAX_ZIP_BYTES = int(os.environ.get("SCAN_MAX_ZIP_BYTES", 100 * 1024 * 1024))
SCAN_MAX_UNCOMPRESSED_BYTES = int(os.environ.get("SCAN_MAX_UNCOMPRESSED_BYTES", 250 * 1024 * 1024))
SCAN_MAX_FILES = int(os.environ.get("SCAN_MAX_FILES", 5000))
SCAN_MAX_FILE_BYTES = int(os.environ.get("SCAN_MAX_FILE_BYTES", 50 * 1024 * 1024))
SCAN_COMPRESSION_RATIO_LIMIT = int(os.environ.get("SCAN_COMPRESSION_RATIO_LIMIT", 200))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", 300))

OSV_QUERY_URL = os.environ.get("OSV_QUERY_URL", "https://api.osv.dev/v1/querybatch")
OSV_VULN_URL = os.environ.get("OSV_VULN_URL", "https://api.osv.dev/v1/vulns/{vuln_id}")
NVD_CVE_URL = os.environ.get("NVD_CVE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
HTTP_TIMEOUT = float(os.environ.get("SCAN_HTTP_TIMEOUT", "15"))
ENABLE_NVD_ENRICHMENT = os.environ.get("ENABLE_NVD_ENRICHMENT", "True").lower() in {"1", "true", "yes"}
ENABLE_PIP_AUDIT = os.environ.get("ENABLE_PIP_AUDIT", "False").lower() in {"1", "true", "yes"}
PIP_AUDIT_PATH = os.environ.get("PIP_AUDIT_PATH", "pip-audit")
ENABLE_GITLEAKS = os.environ.get("ENABLE_GITLEAKS", "False").lower() in {"1", "true", "yes"}
GITLEAKS_PATH = os.environ.get("GITLEAKS_PATH", "gitleaks")

AI_PROVIDER = os.environ.get("AI_PROVIDER", "rule_engine").lower()
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_API_URL = os.environ.get("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "False").lower() in {"1", "true", "yes"}
CELERY_TASK_EAGER_PROPAGATES = False
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "False").lower() in {"1", "true", "yes"}
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in {"1", "true", "yes"}
CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", "False").lower() in {"1", "true", "yes"}
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = bool(SECURE_HSTS_SECONDS)
SECURE_HSTS_PRELOAD = bool(SECURE_HSTS_SECONDS)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"standard": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "root": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO")},
    "loggers": {
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "supplychainx": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO"), "propagate": False},
    },
}
