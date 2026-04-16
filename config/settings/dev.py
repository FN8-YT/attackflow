"""Settings de desarrollo. Heredan de base."""
from .base import *  # noqa: F401,F403
from .base import MIDDLEWARE, INSTALLED_APPS, env

DEBUG = True

# En dev permitimos cualquier host: el entorno está aislado en Docker.
ALLOWED_HOSTS = ["*"]

# Email via Mailpit (servicio Docker en docker-compose.yml).
# Mailpit captura los emails en http://localhost:8025 — nunca llegan a internet.
# Cambia a console.EmailBackend si no quieres levantar Mailpit.
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "mailpit"   # nombre del servicio en docker-compose
EMAIL_PORT = 1025
EMAIL_HOST_USER = ""
EMAIL_HOST_PASSWORD = ""
EMAIL_USE_TLS = False    # Mailpit no necesita TLS en local

# CORS abierto en dev (cuando exista frontend separado).
CORS_ALLOW_ALL_ORIGINS = True

# --- Debug toolbar (opcional, solo si está instalada) ---
try:
    import debug_toolbar  # noqa: F401

    INSTALLED_APPS += ["debug_toolbar"]
    MIDDLEWARE = ["debug_toolbar.middleware.DebugToolbarMiddleware"] + MIDDLEWARE
    INTERNAL_IPS = ["127.0.0.1"]
except ImportError:
    pass
