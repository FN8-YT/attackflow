"""
Settings de PRODUCCIÓN.

Hereda de base.py. Solo sobrescribe lo necesario para un entorno seguro.

Checklist antes de hacer deploy:
  1. Generar SECRET_KEY larga (≥50 chars) y guardarla en .env.prod
  2. Añadir el dominio real a DJANGO_ALLOWED_HOSTS en .env.prod
  3. Generar certificado TLS (Let's Encrypt o similar) en nginx/certs/
  4. Configurar SMTP real en EMAIL_HOST / EMAIL_HOST_USER / EMAIL_HOST_PASSWORD
  5. Correr: docker-compose -f docker-compose.prod.yml run --rm migrate

IMPORTANTE: Nunca poner DEBUG=True en producción.
"""
from .base import *  # noqa: F401,F403
from .base import env, INSTALLED_APPS, MIDDLEWARE  # noqa: F401

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
DEBUG = False

ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS")

# ---------------------------------------------------------------------------
# TLS / HTTPS
# ---------------------------------------------------------------------------
# nginx termina TLS y reenvía X-Forwarded-Proto: https a Daphne.
# Con este header Django sabe que la petición original fue HTTPS.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# nginx ya redirige HTTP→HTTPS (return 301), no duplicar aquí.
SECURE_SSL_REDIRECT = False

# Cookies solo por HTTPS
SESSION_COOKIE_SECURE  = True
CSRF_COOKIE_SECURE     = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY   = True

# HSTS — el browser recordará HTTPS durante 1 año.
# ⚠  Actívalo SOLO cuando HTTPS funcione correctamente.
# Una vez activo, no puedes volver a HTTP sin que los usuarios rompan
# durante el periodo de HSTS.
SECURE_HSTS_SECONDS          = 31_536_000   # 1 año
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD          = True

# Clickjacking & content sniffing
X_FRAME_OPTIONS            = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER  = True   # deprecated en Django 4+ pero inofensivo

# ---------------------------------------------------------------------------
# CORS — solo orígenes explícitos (nunca ALLOW_ALL en prod)
# ---------------------------------------------------------------------------
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS   = env.list("CORS_ALLOWED_ORIGINS", default=[])

# ---------------------------------------------------------------------------
# Email — SMTP real
# ---------------------------------------------------------------------------
EMAIL_BACKEND       = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST          = env("EMAIL_HOST",          default="smtp.gmail.com")
EMAIL_PORT          = env.int("EMAIL_PORT",      default=587)
EMAIL_HOST_USER     = env("EMAIL_HOST_USER",     default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS       = env.bool("EMAIL_USE_TLS",  default=True)
EMAIL_USE_SSL       = env.bool("EMAIL_USE_SSL",  default=False)

# ---------------------------------------------------------------------------
# Archivos estáticos
# collectstatic ---> STATIC_ROOT (servido por nginx, no por Django).
# ManifestStaticFilesStorage añade hash al nombre del archivo para
# cache-busting automático (app.abc123.js en lugar de app.js).
# ---------------------------------------------------------------------------
STATICFILES_STORAGE = (
    "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
)

# ---------------------------------------------------------------------------
# Logging — más silencioso que en dev, pero registra advertencias y errores
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {name} {process:d} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "django":          {"handlers": ["console"], "level": "WARNING",  "propagate": False},
        "django.security": {"handlers": ["console"], "level": "INFO",     "propagate": False},
        "apps":            {"handlers": ["console"], "level": "INFO",     "propagate": False},
        "channels":        {"handlers": ["console"], "level": "WARNING",  "propagate": False},
        "celery":          {"handlers": ["console"], "level": "INFO",     "propagate": False},
    },
}
