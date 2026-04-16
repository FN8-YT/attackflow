"""
Settings de producción.

Aquí endurecemos todo. Cualquier cosa que NO esté hardcodeada
debe llegar como variable de entorno desde el orquestador
(docker-compose prod, ECS, k8s, etc.).
"""
from .base import *  # noqa: F401,F403
from .base import MIDDLEWARE, env  # noqa: F401

DEBUG = False
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS")

# ---------------------------------------------------------------------------
# WhiteNoise — sirve archivos estáticos desde Gunicorn sin necesitar Nginx.
# Imprescindible en Render (no hay Nginx delante en el plan básico).
# Va justo después de SecurityMiddleware para máxima eficiencia.
# ---------------------------------------------------------------------------
MIDDLEWARE = [MIDDLEWARE[0]] + ["whitenoise.middleware.WhiteNoiseMiddleware"] + MIDDLEWARE[1:]

# Compresión Brotli + Gzip y cache con hash en el nombre de archivo.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# ---------------------------------------------------------------------------
# Hardening HTTPS / cookies
# ---------------------------------------------------------------------------
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 60 * 60 * 24 * 365  # 1 año
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

# CORS estricto en prod: solo orígenes explícitos.
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = env.list("CORS_ALLOWED_ORIGINS", default=[])

# ---------------------------------------------------------------------------
# Email — Resend (producción)
#
# Resend es el proveedor recomendado: 3.000 emails/mes gratis, sin
# configurar servidor SMTP propio, API key en segundos.
#
# Setup:
#   1. Crea cuenta en https://resend.com (gratis)
#   2. Ve a Settings → API Keys → Create API Key
#   3. Ve a Domains → Add Domain → verifica tu dominio con DNS
#   4. Añade estas variables al .env de producción:
#
#      EMAIL_HOST_PASSWORD=re_xxxxxxxxxxxxxxxxxxxx   ← tu API key de Resend
#      DEFAULT_FROM_EMAIL=AttackFlow <noreply@tudominio.com>
#
# SMTP de Resend: host=smtp.resend.com, port=587, user="resend", TLS=True
# ---------------------------------------------------------------------------
EMAIL_BACKEND  = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST     = env("EMAIL_HOST", default="smtp.resend.com")
EMAIL_PORT     = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="resend")   # siempre "resend" con Resend
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")             # tu API key: re_xxxxx
EMAIL_USE_TLS  = True
EMAIL_TIMEOUT  = 10
