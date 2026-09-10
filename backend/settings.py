"""Django settings for PhishGuard."""

import os
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    """Read a conventional boolean value from the environment."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: list[str] | None = None) -> list[str]:
    """Read a comma-separated environment variable as a clean list."""
    value = os.getenv(name)
    if not value:
        return default or []
    return [item.strip() for item in value.split(",") if item.strip()]


DEBUG = env_bool("DJANGO_DEBUG", default=True)
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is false."
        )
    SECRET_KEY = "django-insecure-local-development-only-change-before-deployment"
ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
    default=["localhost", "127.0.0.1", "[::1]"],
)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "corsheaders",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "api.middleware.RequestIDMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
if not DEBUG:
    MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")

ROOT_URLCONF = "backend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "backend.wsgi.application"
ASGI_APPLICATION = "backend.asgi.application"

database_url = os.getenv("DATABASE_URL")
if database_url:
    DATABASES = {
        "default": dj_database_url.parse(
            database_url,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
elif DEBUG:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    raise ImproperlyConfigured("DATABASE_URL must be set when DJANGO_DEBUG is false.")

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CORS_ALLOW_ALL_ORIGINS = env_bool(
    "DJANGO_CORS_ALLOW_ALL_ORIGINS",
    default=DEBUG,
)
CORS_ALLOWED_ORIGINS = env_list("DJANGO_CORS_ALLOWED_ORIGINS")

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", default=not DEBUG)
SESSION_COOKIE_SECURE = env_bool("DJANGO_SESSION_COOKIE_SECURE", default=not DEBUG)
CSRF_COOKIE_SECURE = env_bool("DJANGO_CSRF_COOKIE_SECURE", default=not DEBUG)
SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_SECURE_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool(
    "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=False,
)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", default=False)

PHISHGUARD_GEOLOCATION_ENABLED = env_bool(
    "PHISHGUARD_GEOLOCATION_ENABLED",
    default=False,
)
PHISHGUARD_GEOLOCATION_TIMEOUT_SECONDS = float(
    os.getenv("PHISHGUARD_GEOLOCATION_TIMEOUT_SECONDS", "2")
)
try:
    PHISHGUARD_SCAN_RETENTION_DAYS = int(
        os.getenv("PHISHGUARD_SCAN_RETENTION_DAYS", "30")
    )
except ValueError as exc:
    raise ImproperlyConfigured(
        "PHISHGUARD_SCAN_RETENTION_DAYS must be a positive integer."
    ) from exc
if PHISHGUARD_SCAN_RETENTION_DAYS < 1:
    raise ImproperlyConfigured(
        "PHISHGUARD_SCAN_RETENTION_DAYS must be a positive integer."
    )
PHISHGUARD_ML_ENABLED = env_bool("PHISHGUARD_ML_ENABLED", default=False)
PHISHGUARD_MODEL_PATH = Path(
    os.getenv(
        "PHISHGUARD_MODEL_PATH",
        BASE_DIR / "ml_models" / "phishguard_cnn.h5",
    )
)
PHISHGUARD_TOKENIZER_PATH = Path(
    os.getenv(
        "PHISHGUARD_TOKENIZER_PATH",
        BASE_DIR / "ml_models" / "tokenizer.json",
    )
)
PHISHGUARD_ML_WEIGHT = float(os.getenv("PHISHGUARD_ML_WEIGHT", "0.6"))
PHISHGUARD_PHISHING_THRESHOLD = float(os.getenv("PHISHGUARD_PHISHING_THRESHOLD", "50"))

if not 0.0 <= PHISHGUARD_ML_WEIGHT <= 1.0:
    raise ImproperlyConfigured("PHISHGUARD_ML_WEIGHT must be between 0 and 1.")
if not 0.0 <= PHISHGUARD_PHISHING_THRESHOLD <= 100.0:
    raise ImproperlyConfigured(
        "PHISHGUARD_PHISHING_THRESHOLD must be between 0 and 100."
    )

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "backend.exceptions.api_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.getenv("PHISHGUARD_ANON_RATE", "60/min"),
        "user": os.getenv("PHISHGUARD_USER_RATE", "300/min"),
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "PhishGuard API",
    "DESCRIPTION": "URL phishing analysis and trusted-domain administration API.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "PREPROCESSING_HOOKS": ["backend.schema.exclude_legacy_api_routes"],
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "request_context": {
            "()": "backend.logging.RequestContextFilter",
        }
    },
    "formatters": {
        "json": {
            "()": "backend.logging.JSONFormatter",
        },
        "development": {
            "format": "{asctime} {levelname} {name} request_id={request_id} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "development" if DEBUG else "json",
            "filters": ["request_context"],
        }
    },
    "root": {
        "handlers": ["console"],
        "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
    },
}
