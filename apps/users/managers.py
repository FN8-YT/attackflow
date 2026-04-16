"""
Manager personalizado para el modelo User.

Necesitamos uno propio porque el de Django espera `username`, y
nosotros hemos decidido usar el email como identificador. Sin este
manager, `createsuperuser` se rompe.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib.auth.models import BaseUserManager

if TYPE_CHECKING:
    from .models import User


class UserManager(BaseUserManager["User"]):
    """Manager que crea usuarios identificándose por email."""

    use_in_migrations = True

    def _create_user(self, email: str, password: str | None, **extra_fields: Any) -> "User":
        """Método privado común a usuarios y superusuarios."""
        if not email:
            raise ValueError("El email es obligatorio para crear un usuario.")

        # normalize_email pasa el dominio a minúsculas (parte izquierda sin tocar).
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        # set_password hashea con el hasher por defecto (PBKDF2 en Django).
        # NUNCA guardes la contraseña en texto plano.
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields: Any) -> "User":
        """Crea un usuario normal (sin privilegios)."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str | None = None, **extra_fields: Any) -> "User":
        """Crea un superusuario (acceso al admin de Django)."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        # Forzamos estos flags aunque el que llama intente lo contrario.
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Un superusuario debe tener is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Un superusuario debe tener is_superuser=True.")

        return self._create_user(email, password, **extra_fields)
