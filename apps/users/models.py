"""
Modelo de usuario personalizado.

Decisiones de diseño:
- Hereda de AbstractUser (no AbstractBaseUser): nos ahorra reimplementar
  permisos, grupos, is_active/is_staff, etc. Todo compatible con admin.
- `username` se elimina poniéndolo a None. El identificador es el email.
- `plan` modela los niveles de suscripción. Se implementa como TextChoices
  para que sea type-safe, visible en el admin y fácil de extender.
- USERNAME_FIELD = "email" le dice a Django que login/createsuperuser
  deben pedir email.
- REQUIRED_FIELDS = [] porque el email ya es USERNAME_FIELD; Django
  siempre lo pide, no hace falta repetirlo aquí.
"""
from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from .managers import UserManager


class PlanChoices(models.TextChoices):
    """Niveles de suscripción del SaaS."""

    FREE = "free", _("Free")
    PREMIUM = "premium", _("Premium")
    ADMIN = "admin", _("Admin")


# Configuración centralizada de features por plan.
# Cada clave es un feature flag; el valor dice qué planes lo tienen.
PLAN_CONFIG: dict[str, dict] = {
    PlanChoices.FREE: {
        "monthly_quota": 5,
        "scan_modes": ["passive"],
        "pdf_export": False,
        "advanced_scanners": False,
        "monitoring_targets": 1,
        "label": "Free",
        "price": "0",
    },
    PlanChoices.PREMIUM: {
        "monthly_quota": 200,
        "scan_modes": ["passive", "active"],
        "pdf_export": True,
        "advanced_scanners": True,
        "monitoring_targets": 10,
        "label": "Premium",
        "price": "29",
    },
    PlanChoices.ADMIN: {
        "monthly_quota": 10_000,
        "scan_modes": ["passive", "active"],
        "pdf_export": True,
        "advanced_scanners": True,
        "monitoring_targets": 500,
        "label": "Admin",
        "price": "—",
    },
}


# Config que se usa cuando DISABLE_PLAN_LIMITS=True.
# Desbloquea todas las features sin tocar el plan real del usuario.
_UNLIMITED_CONFIG: dict = {
    "monthly_quota": 999_999,
    "scan_modes": ["passive", "active"],
    "pdf_export": True,
    "advanced_scanners": True,
    "monitoring_targets": 500,
    "label": "Unlimited (Dev)",
    "price": "—",
}


class User(AbstractUser):
    """Usuario del sistema, identificado por email."""

    # Eliminamos el campo username heredado de AbstractUser.
    username = None  # type: ignore[assignment]

    email = models.EmailField(
        _("email address"),
        unique=True,
        help_text=_("Usado como identificador único para iniciar sesión."),
    )

    plan = models.CharField(
        _("plan"),
        max_length=16,
        choices=PlanChoices.choices,
        default=PlanChoices.FREE,
        help_text=_("Nivel de suscripción actual del usuario."),
    )

    is_verified = models.BooleanField(
        _("email verified"),
        default=False,
        help_text=_(
            "Indica si el usuario ha confirmado su dirección de email. "
            "Los usuarios no verificados no pueden acceder a la plataforma."
        ),
    )

    # Le decimos a Django qué campo es el identificador.
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    # Usamos nuestro manager personalizado.
    objects = UserManager()  # type: ignore[misc]

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        ordering = ("-date_joined",)

    def save(self, *args, **kwargs) -> None:
        # Los superusuarios siempre se consideran verificados:
        # createsuperuser no pasa por el flujo de email.
        if self.is_superuser:
            self.is_verified = True
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.email

    # -------------------------------------------------------------------
    # Helpers de dominio. Los centralizamos aquí para no repartir lógica
    # de negocio por views y templates. Si mañana cambiamos los nombres
    # de los planes, solo tocamos estos métodos.
    # -------------------------------------------------------------------
    @property
    def is_premium(self) -> bool:
        return self.plan in {PlanChoices.PREMIUM, PlanChoices.ADMIN}

    @property
    def monthly_audit_quota(self) -> int:
        """Cuántas auditorías puede lanzar por mes según su plan."""
        return self.plan_config["monthly_quota"]

    @property
    def plan_config(self) -> dict:
        """
        Devuelve la configuración completa del plan actual.

        Si DISABLE_PLAN_LIMITS=True en settings, devuelve una config
        sin restricciones para facilitar el testing en desarrollo.
        """
        from django.conf import settings

        if getattr(settings, "DISABLE_PLAN_LIMITS", False):
            return _UNLIMITED_CONFIG
        return PLAN_CONFIG[PlanChoices(self.plan)]

    def has_feature(self, feature: str) -> bool:
        """Comprueba si el plan del usuario incluye una feature concreta."""
        return bool(self.plan_config.get(feature, False))
