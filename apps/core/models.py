"""
Modelos base y mixins reutilizables.

Todo modelo del dominio debería heredar de TimeStampedModel para tener
timestamps consistentes. Esto es importante cuando haces auditoría
(¿cuándo se creó esto?, ¿cuándo se actualizó?) — y en un producto de
seguridad la trazabilidad no es negociable.
"""
from django.db import models


class TimeStampedModel(models.Model):
    """Modelo abstracto con timestamps automáticos."""

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Fecha de creación del registro.",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Última modificación del registro.",
    )

    class Meta:
        abstract = True  # No genera tabla propia; solo aporta columnas.
        get_latest_by = "created_at"
        ordering = ("-created_at",)
