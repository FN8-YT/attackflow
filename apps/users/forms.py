"""
Formularios de autenticación.

Usamos las clases de `django.contrib.auth.forms` como base porque
ya hacen bien las partes delicadas: hasheo con `set_password`,
validaciones de password (longitud, similitud, común, numérico)
usando AUTH_PASSWORD_VALIDATORS del settings.

No reinventes la rueda: extiende, no copies.
"""
from __future__ import annotations

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import User


class RegistrationForm(UserCreationForm):
    """
    Formulario de registro. Pide email + password + confirmación.
    Los validadores de password se aplican automáticamente porque
    heredamos de UserCreationForm.
    """

    class Meta:
        model = User
        fields = ("email",)  # password1/password2 los añade UserCreationForm

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Un par de ajustes cosméticos y de accesibilidad.
        self.fields["email"].widget.attrs.update(
            {"autofocus": True, "autocomplete": "email"}
        )
        self.fields["password1"].widget.attrs.update({"autocomplete": "new-password"})
        self.fields["password2"].widget.attrs.update({"autocomplete": "new-password"})


class EmailAuthenticationForm(AuthenticationForm):
    """
    AuthenticationForm por defecto etiqueta el campo como "Username".
    Como nosotros identificamos por email, lo renombramos visualmente.
    La lógica de validación no cambia: usa USERNAME_FIELD del modelo.

    confirm_login_allowed: bloquea el login de usuarios no verificados
    con un mensaje que incluye el enlace de reenvío, antes de que Django
    emita la sesión — la primera línea de defensa.
    """

    username = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autofocus": True, "autocomplete": "email"}),
    )

    def confirm_login_allowed(self, user) -> None:
        """
        Hook de AuthenticationForm: lanza ValidationError si el usuario
        no debe poder iniciar sesión.
        Llamado DESPUÉS de validar credenciales, ANTES de crear la sesión.
        """
        super().confirm_login_allowed(user)  # comprueba is_active

        if not getattr(user, "is_verified", True):
            raise ValidationError(
                _(
                    "Tu cuenta no está verificada. "
                    "Revisa tu email o solicita un nuevo enlace."
                ),
                code="email_not_verified",
            )
