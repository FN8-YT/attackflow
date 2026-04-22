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
        self.fields["email"].widget.attrs.update(
            {"autofocus": True, "autocomplete": "email"}
        )
        self.fields["password1"].widget.attrs.update({"autocomplete": "new-password"})
        self.fields["password2"].widget.attrs.update({"autocomplete": "new-password"})


class EmailAuthenticationForm(AuthenticationForm):
    """
    AuthenticationForm por defecto etiqueta el campo como "Username".
    Lo renombramos a "Email" para que coincida con nuestro modelo.
    """

    username = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autofocus": True, "autocomplete": "email"}),
    )
