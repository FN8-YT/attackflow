"""
Formularios para Continuous Monitoring.

MonitorTargetForm:
  - Valida nombre, URL y check_interval.
  - Sin restricciones por plan: todos los intervalos disponibles
    y sin límite de targets por usuario.
"""
from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import CheckInterval, MonitorTarget


class MonitorTargetForm(forms.ModelForm):
    """Formulario para crear / editar un MonitorTarget."""

    class Meta:
        model = MonitorTarget
        fields = ["name", "url", "check_interval", "check_sensitive_paths"]
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
            "check_sensitive_paths": forms.CheckboxInput(),
        }
        labels = {
            "name":                  _("Nombre"),
            "url":                   _("URL a monitorizar"),
            "check_interval":        _("Intervalo de comprobación"),
            "check_sensitive_paths": _("Escaneo de paths sensibles"),
        }
        help_texts = {
            "url":            _("Debe ser https:// o http://. Solo IPs públicas."),
            "check_interval": _(
                "Intervalos ⚡ live (5s/30s/1min) solo comprueban uptime + headers + SSL. "
                "El escaneo de paths sensibles se ejecuta en intervalos ≥ 5 min."
            ),
            "check_sensitive_paths": _(
                "Sondea admin panels, .env, .git, backups, etc. "
                "en cada comprobación. Útil para pentesting de tu propia infraestructura."
            ),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        # Todos los intervalos disponibles para todos los usuarios.
        self.fields["check_interval"].choices = list(CheckInterval.choices)
