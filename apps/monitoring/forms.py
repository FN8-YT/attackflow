"""
Formularios para Continuous Monitoring.

MonitorTargetForm:
  - Valida nombre, URL y check_interval.
  - Aplica plan gating: FREE → max 1 target, PREMIUM → max 10.
  - Muestra un mensaje claro si el usuario ha alcanzado su límite.
"""
from __future__ import annotations

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.users.models import PLAN_CONFIG, PlanChoices

from .models import CheckInterval, MonitorTarget


# Límite de targets por plan.
MONITOR_LIMITS: dict[str, int] = {
    PlanChoices.FREE:    1,
    PlanChoices.PREMIUM: 10,
    PlanChoices.ADMIN:   500,
}


def get_monitor_limit(user) -> int:
    """Devuelve el número máximo de targets que puede crear el usuario."""
    if getattr(settings, "DISABLE_PLAN_LIMITS", False):
        return MONITOR_LIMITS[PlanChoices.ADMIN]
    return MONITOR_LIMITS.get(user.plan, 1)


class MonitorTargetForm(forms.ModelForm):
    """Formulario para crear / editar un MonitorTarget."""

    class Meta:
        model = MonitorTarget
        fields = ["name", "url", "check_interval"]
        widgets = {
            "name": forms.TextInput(attrs={
                "placeholder": "Mi servidor de producción",
                "autocomplete": "off",
            }),
            "url": forms.URLInput(attrs={
                "placeholder": "https://example.com",
                "autocomplete": "off",
            }),
            "check_interval": forms.Select(),
        }
        labels = {
            "name":           _("Nombre"),
            "url":            _("URL a monitorizar"),
            "check_interval": _("Intervalo de comprobación"),
        }
        help_texts = {
            "url": _("Debe ser https:// o http://. Solo IPs públicas."),
            "check_interval": _("Con qué frecuencia se comprobará el objetivo."),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

        # Resaltar check_interval=5min solo para premium.
        if user and not user.is_premium:
            # Filtra la opción de 5 min para usuarios free.
            self.fields["check_interval"].choices = [
                (v, l) for v, l in CheckInterval.choices
                if v != CheckInterval.MIN_5
            ]

    def clean(self):
        cleaned = super().clean()

        # Plan gating: límite de targets.
        if self.user and not self.instance.pk:
            limit = get_monitor_limit(self.user)
            current = MonitorTarget.objects.filter(user=self.user).count()
            if current >= limit:
                plan_label = self.user.get_plan_display()
                raise ValidationError(
                    f"Has alcanzado el límite de {limit} target(s) para el plan {plan_label}. "
                    f"Actualiza a Premium para monitorizar hasta 10 objetivos."
                )

        return cleaned
