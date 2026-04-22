"""
Validador de contraseñas personalizado para AttackFlow.

Reglas de complejidad:
  - Al menos 1 letra mayúscula.
  - Al menos 1 letra minúscula.
  - Al menos 1 dígito o carácter especial.

La longitud mínima (5 caracteres) se configura en settings.py
mediante MinimumLengthValidator estándar de Django.
"""
from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class ComplexityValidator:
    """
    Valida que la contraseña contenga al menos:
    - Una letra mayúscula (A-Z).
    - Una letra minúscula (a-z).
    - Un dígito (0-9) o un carácter especial.
    """

    def validate(self, password: str, user=None) -> None:
        errors: list[ValidationError] = []

        if not re.search(r"[A-Z]", password):
            errors.append(
                ValidationError(
                    _("La contraseña debe contener al menos una letra mayúscula."),
                    code="password_no_upper",
                )
            )
        if not re.search(r"[a-z]", password):
            errors.append(
                ValidationError(
                    _("La contraseña debe contener al menos una letra minúscula."),
                    code="password_no_lower",
                )
            )
        if not re.search(r"[0-9\W_]", password):
            errors.append(
                ValidationError(
                    _("La contraseña debe contener al menos un número o símbolo (!, @, #, etc.)."),
                    code="password_no_digit_or_symbol",
                )
            )

        if errors:
            raise ValidationError(errors)

    def get_help_text(self) -> str:
        return _(
            "Tu contraseña debe contener al menos una mayúscula, "
            "una minúscula y un número o símbolo."
        )
