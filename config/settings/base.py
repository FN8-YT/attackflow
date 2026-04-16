"""
Settings base — comunes a todos los entornos.

Reglas:
- Nada que sea sensible debe estar hardcodeado aquí; todo viene del entorno.
- `dev.py` y `prod.py` heredan de este archivo y solo cambian lo necesario.
- Los defaults inseguros (DEBUG=True, ALLOWED_HOSTS=*) NO viven aquí: son
  responsabilidad explícita de cada entorno.
"""
from pathlib import Path

import environ

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# BASE_DIR apunta a la raíz del proyecto (donde está manage.py).
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Carga de variables de entorno
# ---------------------------------------------------------------------------
env = environ.Env(
    DJANGO_DEBUG=(bool, False),
    DJANGO_ALLOWED_HOSTS=(list, []),
    DISABLE_PLAN_LIMITS=(bool, False),
)

# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------
# Cuando es True, todos los usuarios tienen acceso ilimitado a todas las
# features (cuota, scanners activos, PDF export). Útil para testing/dev.
# En producción NUNCA debe estar activo.
DISABLE_PLAN_LIMITS = env("DISABLE_PLAN_LIMITS")

# Si existe un .env en la raíz, se carga (cómodo en local).
# En producción las variables vienen del orquestador (no del archivo).
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

# ---------------------------------------------------------------------------
# Núcleo
# ---------------------------------------------------------------------------
SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS")

# ---------------------------------------------------------------------------
# Apps
# ---------------------------------------------------------------------------
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "axes",  # protección contra brute force
]

LOCAL_APPS = [
    "apps.core",
    "apps.users",
    "apps.audits",
    "apps.reports",
    "apps.monitoring",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ---------------------------------------------------------------------------
# Middleware
# El orden importa. Anotaciones rápidas:
# - SecurityMiddleware: cabeceras HSTS, redirect a HTTPS, etc.
# - CorsMiddleware: lo más arriba posible, antes de CommonMiddleware.
# - AxesMiddleware: al final, para que vea el resultado de la auth.
# ---------------------------------------------------------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",
    # Debe ir DESPUÉS de AuthenticationMiddleware (necesita request.user)
    # y DESPUÉS de SessionMiddleware (necesita request.session).
    "apps.users.middleware.EmailVerificationMiddleware",
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
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
# Render (y otros PaaS) inyectan DATABASE_URL como string único.
# En dev usamos variables individuales. Soportamos ambos formatos.
_db_url = env("DATABASE_URL", default=None)
if _db_url:
    # Formato PaaS: postgres://user:pass@host:5432/dbname
    DATABASES = {"default": env.db_url_config(_db_url) | {"CONN_MAX_AGE": 60}}
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB"),
            "USER": env("POSTGRES_USER"),
            "PASSWORD": env("POSTGRES_PASSWORD"),
            "HOST": env("POSTGRES_HOST"),
            "PORT": env("POSTGRES_PORT"),
            "CONN_MAX_AGE": 60,
        }
    }

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
# Todavía no existe el modelo, pero declaramos AUTH_USER_MODEL desde el
# principio para no tener que hacer una migración dolorosa más adelante.
AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = [
    # Axes va PRIMERO para poder bloquear antes de validar credenciales.
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# URLs de redirección post-login/logout. Usamos nombres de ruta
# en vez de hardcodear paths: si cambia la URL, no hay que venir aquí.
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "users:dashboard"
LOGOUT_REDIRECT_URL = "login"

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
# EMAIL_BACKEND se define en dev.py (console) y prod.py (smtp).
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="AttackFlow <noreply@attackflow.io>")
SERVER_EMAIL = DEFAULT_FROM_EMAIL  # para errores internos de Django

# Ventana de validez del token de verificación: 24 horas.
# Ajustable sin tocar el código; cambiar a int (segundos).
EMAIL_VERIFY_MAX_AGE: int = 60 * 60 * 24

# ---------------------------------------------------------------------------
# Internacionalización
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "es-es"
TIME_ZONE = "Europe/Madrid"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Estáticos y media
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Cache (Redis)
# ---------------------------------------------------------------------------
# REDIS_URL es la URL base. En dev tenemos URLs separadas por DB number.
# En Render/Upstash se usa la misma URL para todo (no soportan multi-DB).
# Fallback a locmem si no hay REDIS_URL (evita crashear en arranque).
_redis_url = env("REDIS_URL", default="")

if _redis_url:
    # Opciones SSL para Upstash (rediss://). `ssl_cert_reqs=none` desactiva
    # la verificación estricta del cert, que Upstash no firma con CA pública.
    _redis_cache_options = {"CLIENT_CLASS": "django_redis.client.DefaultClient"}
    if _redis_url.startswith("rediss://"):
        _redis_cache_options["CONNECTION_POOL_KWARGS"] = {"ssl_cert_reqs": None}

    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": _redis_url,
            "OPTIONS": _redis_cache_options,
        }
    }
else:
    # Sin Redis: memoria local (solo sirve para tests / arranque sin cache).
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------
# Si se definen por separado (dev), se usan directamente.
# Si no, se reutiliza REDIS_URL (Render/Upstash con un solo Redis).
CELERY_BROKER_URL = env("CELERY_BROKER_URL", default=_redis_url)
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", default=_redis_url)
CELERY_TASK_ACKS_LATE = True              # Reentregar si el worker muere
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1     # Justo para tareas largas como auditorías
CELERY_TASK_TIME_LIMIT = 300              # Hard kill a los 5 min
CELERY_TASK_SOFT_TIME_LIMIT = 270         # Aviso a los 4:30
CELERY_TIMEZONE = TIME_ZONE

# SSL para Upstash Redis (rediss://) — solo si el broker es SSL.
if CELERY_BROKER_URL and CELERY_BROKER_URL.startswith("rediss://"):
    import ssl
    CELERY_BROKER_USE_SSL = {"ssl_cert_reqs": ssl.CERT_NONE}
    CELERY_REDIS_BACKEND_USE_SSL = {"ssl_cert_reqs": ssl.CERT_NONE}

# CELERY_TASK_ALWAYS_EAGER: cuando es True, las tasks se ejecutan
# síncronamente en el mismo proceso que las invoca (sin pasar por el
# broker). Imprescindible en Render free tier (no hay worker).
# Valor por defecto True si no hay broker configurado.
CELERY_TASK_ALWAYS_EAGER = env.bool(
    "CELERY_TASK_ALWAYS_EAGER",
    default=not bool(CELERY_BROKER_URL),
)
CELERY_TASK_EAGER_PROPAGATES = True   # Re-lanza excepciones en modo eager

# Beat schedule: tarea periódica de monitorización.
# Se ejecuta cada 60s. La lógica "is_due" dentro de la tarea
# decide qué targets necesitan ser comprobados según su intervalo.
CELERY_BEAT_SCHEDULE = {
    "run-due-monitoring-checks": {
        "task": "apps.monitoring.tasks.run_due_monitoring_checks",
        "schedule": 60.0,  # segundos
    },
}

# ---------------------------------------------------------------------------
# DRF
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "60/min",
        "anon": "20/min",
    },
}

# ---------------------------------------------------------------------------
# django-axes (brute force)
# ---------------------------------------------------------------------------
AXES_FAILURE_LIMIT = 10          # intentos fallidos antes de bloquear
AXES_COOLOFF_TIME = 1            # horas que dura el bloqueo
AXES_LOCKOUT_PARAMETERS = ["ip_address", "username"]
AXES_RESET_ON_SUCCESS = True     # limpia el contador al loguearse bien

# ---------------------------------------------------------------------------
# Logging
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
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "apps": {"handlers": ["console"], "level": "DEBUG", "propagate": False},
    },
}
