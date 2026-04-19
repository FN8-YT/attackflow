"""
Settings de desarrollo local.

Hereda todo de base.py y solo sobrescribe lo que cambia en dev:
- DEBUG y ALLOWED_HOSTS abiertos (entorno aislado en Docker).
- Email capturado por Mailpit en localhost:8025 (nunca llega a internet).
- CORS abierto (útil cuando se usa un frontend separado en dev).
- django-debug-toolbar activado si está instalado.
"""
from .base import *  # noqa: F401,F403
from .base import INSTALLED_APPS, MIDDLEWARE

DEBUG = True

# Aceptar cualquier host en dev: el contenedor no es accesible desde internet.
ALLOWED_HOSTS = ["*"]

# ---------------------------------------------------------------------------
# Email — Mailpit (captura SMTP local)
#
# Mailpit es un servidor SMTP falso que atrapa todos los emails y los
# muestra en una interfaz web en http://localhost:8025
# Los emails NO se envían a internet.
#
# Levantar junto con docker-compose.yml (servicio "mailpit" incluido).
# Si prefieres no usar Docker para email, cambia a:
#   EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
# ---------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "mailpit"   # nombre del servicio en docker-compose
EMAIL_PORT = 1025
EMAIL_HOST_USER = ""
EMAIL_HOST_PASSWORD = ""
EMAIL_USE_TLS = False

# ---------------------------------------------------------------------------
# CORS — abierto en dev
# ---------------------------------------------------------------------------
CORS_ALLOW_ALL_ORIGINS = True

# ---------------------------------------------------------------------------
# django-debug-toolbar (opcional)
# Se activa automáticamente si la librería está instalada (está en dev.txt).
# Accesible en la barra lateral derecha de cada página Django.
# ---------------------------------------------------------------------------
try:
    import debug_toolbar  # noqa: F401

    INSTALLED_APPS = [*INSTALLED_APPS, "debug_toolbar"]
    MIDDLEWARE = ["debug_toolbar.middleware.DebugToolbarMiddleware", *MIDDLEWARE]
    INTERNAL_IPS = ["127.0.0.1"]
except ImportError:
    pass
