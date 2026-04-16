"""Formularios de la app audits."""
from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError

from .models import Audit, ScanMode
from .scanners import SCANNER_REGISTRY, get_available_scanners
from .validators import resolve_and_validate


class AuditForm(forms.ModelForm):
    """
    Formulario para crear una auditoría.

    Incluye:
    - target_url: URL del objetivo.
    - scan_mode: pasivo o activo (filtrado por plan).
    - selected_scanners: checkboxes de módulos a ejecutar.
    """

    selected_scanners = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(),
        label="Módulos de análisis",
        help_text="Selecciona qué módulos ejecutar. Desmarca los que no necesites.",
    )

    class Meta:
        model = Audit
        fields = ("target_url", "scan_mode")
        widgets = {
            "target_url": forms.URLInput(
                attrs={
                    "placeholder": "https://example.com",
                    "autofocus": True,
                    "autocomplete": "off",
                }
            ),
            "scan_mode": forms.Select(
                attrs={"class": "form-select", "id": "id_scan_mode"}
            ),
        }
        labels = {
            "scan_mode": "Modo de escaneo",
        }
        help_texts = {
            "scan_mode": (
                "Pasivo: solo analiza respuestas. "
                "Activo: envía payloads de prueba (XSS, SQLi, misconfig)."
            ),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._user = user

        # Filtrar modos según plan del usuario.
        if user:
            allowed = user.plan_config.get("scan_modes", ["passive"])
            choices = [
                (c.value, c.label) for c in ScanMode
                if c.value in allowed
            ]
            self.fields["scan_mode"].choices = choices

        # Construir choices de scanners con TODA la metadata.
        # Todos aparecen como opciones; el template usa data-attrs
        # para mostrar locks y tooltips según tier.
        all_choices = []
        for entry in SCANNER_REGISTRY:
            meta = entry["meta"]
            all_choices.append((meta.key, meta.label))
        self.fields["selected_scanners"].choices = all_choices

        # Defaults: marcar los que correspondan por defecto.
        has_advanced = user.has_feature("advanced_scanners") if user else False
        # Por defecto: todos los disponibles marcados.
        default_keys = [
            m.key for m in get_available_scanners("active", has_advanced)
            if m.default
        ]
        self.fields["selected_scanners"].initial = default_keys

    def clean_target_url(self) -> str:
        url = self.cleaned_data["target_url"]
        try:
            resolve_and_validate(url)
        except ValidationError:
            raise
        return url

    def clean_scan_mode(self) -> str:
        mode = self.cleaned_data["scan_mode"]
        if self._user:
            allowed = self._user.plan_config.get("scan_modes", ["passive"])
            if mode not in allowed:
                raise ValidationError(
                    "Tu plan no permite el modo de escaneo activo. "
                    "Actualiza a Premium."
                )
        return mode

    def clean_selected_scanners(self) -> list[str]:
        """
        Validar la selección de scanners contra el plan del usuario.
        Eliminar silenciosamente cualquier scanner al que no tenga acceso
        (protección contra manipulación del HTML).
        """
        selected = self.cleaned_data.get("selected_scanners", [])
        if not selected:
            return []

        # Determinar qué scanners tiene acceso este usuario.
        has_advanced = (
            self._user.has_feature("advanced_scanners") if self._user else False
        )
        scan_mode = self.cleaned_data.get("scan_mode", "passive")
        available = get_available_scanners(scan_mode, has_advanced)
        available_keys = {m.key for m in available}

        # Filtrar: solo los que están en su tier permitido.
        validated = [key for key in selected if key in available_keys]
        return validated

    def save(self, commit=True):
        """Guardar la selección de scanners en el campo JSON del modelo."""
        audit = super().save(commit=False)
        audit.selected_scanners = self.cleaned_data.get("selected_scanners", [])
        if commit:
            audit.save()
        return audit
