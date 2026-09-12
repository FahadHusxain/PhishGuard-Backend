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
    "drf_spectacular_sidecar",
    "corsheaders",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "api.middleware.BrowserSecurityHeadersMiddleware",
    "api.middleware.RequestIDMiddleware",
    "api.middleware.APIRequestLimitsMiddleware",
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
        "OPTIONS": {"min_length": 12},
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
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

try:
    DATA_UPLOAD_MAX_MEMORY_SIZE = int(
        os.getenv("PHISHGUARD_MAX_REQUEST_BYTES", str(16 * 1024))
    )
    DATA_UPLOAD_MAX_NUMBER_FIELDS = int(
        os.getenv("PHISHGUARD_MAX_REQUEST_FIELDS", "20")
    )
    PHISHGUARD_NUM_PROXIES = int(os.getenv("PHISHGUARD_NUM_PROXIES", "0"))
    PHISHGUARD_STATS_CACHE_SECONDS = int(
        os.getenv("PHISHGUARD_STATS_CACHE_SECONDS", "10")
    )
except ValueError as exc:
    raise ImproperlyConfigured(
        "Request limits, cache duration, and PHISHGUARD_NUM_PROXIES must be integers."
    ) from exc
if (
    DATA_UPLOAD_MAX_MEMORY_SIZE < 1024
    or DATA_UPLOAD_MAX_NUMBER_FIELDS < 1
    or PHISHGUARD_STATS_CACHE_SECONDS < 1
):
    raise ImproperlyConfigured(
        "Request size, field limits, and cache duration must be positive."
    )
if PHISHGUARD_NUM_PROXIES < 0:
    raise ImproperlyConfigured("PHISHGUARD_NUM_PROXIES cannot be negative.")

CACHE_URL = os.getenv("CACHE_URL")
if CACHE_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": CACHE_URL,
            "TIMEOUT": 300,
            "OPTIONS": {
                "socket_connect_timeout": 2,
                "socket_timeout": 2,
            },
            "KEY_PREFIX": "phishguard",
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "phishguard-development",
            "TIMEOUT": 300,
        }
    }

CORS_ALLOW_ALL_ORIGINS = env_bool(
    "DJANGO_CORS_ALLOW_ALL_ORIGINS",
    default=DEBUG,
)
CORS_ALLOWED_ORIGINS = env_list("DJANGO_CORS_ALLOWED_ORIGINS")
CORS_EXPOSE_HEADERS = ["X-Request-ID", "Retry-After"]
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", default=not DEBUG)
SESSION_COOKIE_SECURE = env_bool("DJANGO_SESSION_COOKIE_SECURE", default=not DEBUG)
CSRF_COOKIE_SECURE = env_bool("DJANGO_CSRF_COOKIE_SECURE", default=not DEBUG)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
try:
    SESSION_COOKIE_AGE = int(
        os.getenv("DJANGO_ADMIN_SESSION_SECONDS", str(8 * 60 * 60))
    )
except ValueError as exc:
    raise ImproperlyConfigured(
        "DJANGO_ADMIN_SESSION_SECONDS must be a positive integer."
    ) from exc
if SESSION_COOKIE_AGE < 300:
    raise ImproperlyConfigured(
        "DJANGO_ADMIN_SESSION_SECONDS must be at least 300 seconds."
    )
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
PHISHGUARD_ML_SHADOW_ENABLED = env_bool("PHISHGUARD_ML_SHADOW_ENABLED", default=False)
PHISHGUARD_V4_ENSEMBLE_PATH = Path(
    os.getenv(
        "PHISHGUARD_V4_ENSEMBLE_PATH",
        BASE_DIR / "ml_models" / "url_ensemble_candidate_v4.npz",
    )
)
PHISHGUARD_V4_LEXICAL_PATH = Path(
    os.getenv(
        "PHISHGUARD_V4_LEXICAL_PATH",
        BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz",
    )
)
PHISHGUARD_V4_STRUCTURAL_PATH = Path(
    os.getenv(
        "PHISHGUARD_V4_STRUCTURAL_PATH",
        BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz",
    )
)
PHISHGUARD_PHISHING_THRESHOLD = float(os.getenv("PHISHGUARD_PHISHING_THRESHOLD", "50"))

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
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
    ],
    "EXCEPTION_HANDLER": "backend.exceptions.api_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.getenv("PHISHGUARD_ANON_RATE", "60/min"),
        "user": os.getenv("PHISHGUARD_USER_RATE", "300/min"),
        "analysis": os.getenv("PHISHGUARD_ANALYSIS_RATE", "30/min"),
        "administration": os.getenv("PHISHGUARD_ADMIN_RATE", "10/min"),
        "read": os.getenv("PHISHGUARD_READ_RATE", "120/min"),
    },
    "NUM_PROXIES": PHISHGUARD_NUM_PROXIES,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "PhishGuard API",
    "DESCRIPTION": "URL phishing analysis and trusted-domain administration API.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "PREPROCESSING_HOOKS": ["backend.schema.exclude_legacy_api_routes"],
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
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
