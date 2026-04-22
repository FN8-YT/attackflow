"""
Modelo de usuario personalizado.

Decisiones de diseño:
- Hereda de AbstractUser (no AbstractBaseUser): nos ahorra reimplementar
  permisos, grupos, is_active/is_staff, etc. Todo compatible con admin.
- `username` se elimina poniéndolo a None. El identificador es el email.
- AttackFlow es completamente gratuito: no existe sistema de planes ni
  restricciones por suscripción. Todos los usuarios tienen acceso total.
- USERNAME_FIELD = "email" le dice a Django que login/createsuperuser
  deben pedir email.
- REQUIRED_FIELDS = [] porque el email ya es USERNAME_FIELD; Django
  siempre lo pide, no hace falta repetirlo aquí.
- No hay verificación de email: el registro da acceso inmediato.
"""
from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from .managers import UserManager


class User(AbstractUser):
    """Usuario del sistema, identificado por email."""

    # Eliminamos el campo username heredado de AbstractUser.
    username = None  # type: ignore[assignment]

    email = models.EmailField(
        _("email address"),
        unique=True,
        help_text=_("Usado como identificador único para iniciar sesión."),
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

    def __str__(self) -> str:
        return self.email
