"""
Settings base — comunes a todos los entornos.

Reglas:
- Nada sensible está hardcodeado aquí; todo viene del .env.
- dev.py hereda de este archivo y solo cambia lo necesario.
- Los defaults inseguros (DEBUG=True, ALLOWED_HOSTS=*) NO viven
  aquí: son responsabilidad explícita de cada entorno.
"""
from pathlib import Path

import environ

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Variables de entorno
# ---------------------------------------------------------------------------
env = environ.Env(
    DJANGO_DEBUG=(bool, False),
    DJANGO_ALLOWED_HOSTS=(list, []),
    DISABLE_PLAN_LIMITS=(bool, False),
)

# Carga el .env de la raíz si existe (dev local).
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------
# True → todos los usuarios tienen cuota ilimitada y todas las features
# activadas (útil para desarrollo/testing). Nunca usar en producción.
DISABLE_PLAN_LIMITS = env("DISABLE_PLAN_LIMITS")

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
    "axes",
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
# Orden importante:
# - SecurityMiddleware: primero, gestiona HTTPS/HSTS.
# - CorsMiddleware: lo más arriba posible.
# - AxesMiddleware: al final, intercepta la respuesta de auth.
# - EmailVerificationMiddleware: después de Auth + Session.
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
# Base de datos — PostgreSQL local (via Docker Compose)
# ---------------------------------------------------------------------------
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
AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = [
    # Axes va PRIMERO: bloquea antes de validar credenciales.
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

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "users:dashboard"
LOGOUT_REDIRECT_URL = "login"

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
# El backend concreto (SMTP / console) lo define cada entorno en su settings.
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="AttackFlow <noreply@attackflow.local>")
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# Ventana de validez del token de verificación de email.
EMAIL_VERIFY_MAX_AGE: int = 60 * 60 * 24  # 24 horas

# ---------------------------------------------------------------------------
# Internacionalización
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "es-es"
TIME_ZONE = "Europe/Madrid"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Archivos estáticos y media
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Cache — Redis local (via Docker Compose)
# ---------------------------------------------------------------------------
# Fallback a locmem si REDIS_URL no está configurado (útil en tests).
_redis_url = env("REDIS_URL", default="")

if _redis_url:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": _redis_url,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

# ---------------------------------------------------------------------------
# Celery — broker y result backend en Redis local
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = env("CELERY_BROKER_URL", default=_redis_url)
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", default=_redis_url)
CELERY_TASK_ACKS_LATE = True              # Reentregar si el worker muere
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1     # Una tarea a la vez (audits son lentos)
CELERY_TASK_TIME_LIMIT = 300              # Hard kill a los 5 min
CELERY_TASK_SOFT_TIME_LIMIT = 270         # SoftTimeLimitExceeded a los 4:30
CELERY_TIMEZONE = TIME_ZONE

# Beat: lanza los checks de monitoring automático cada 60s.
# La lógica "is_due" dentro de run_due_monitoring_checks decide
# qué targets necesitan comprobarse según su intervalo configurado.
CELERY_BEAT_SCHEDULE = {
    "run-due-monitoring-checks": {
        "task": "apps.monitoring.tasks.run_due_monitoring_checks",
        "schedule": 60.0,  # segundos
    },
}

# ---------------------------------------------------------------------------
# Django REST Framework
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
# django-axes — protección contra brute force
# ---------------------------------------------------------------------------
AXES_FAILURE_LIMIT = 10
AXES_COOLOFF_TIME = 1              # horas que dura el bloqueo
AXES_LOCKOUT_PARAMETERS = ["ip_address", "username"]
AXES_RESET_ON_SUCCESS = True

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
