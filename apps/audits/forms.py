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
    - scan_mode: pasivo o activo (todos los modos disponibles para todos).
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

        # Todos los modos de escaneo disponibles para todos los usuarios.
        self.fields["scan_mode"].choices = [(c.value, c.label) for c in ScanMode]

        # Todos los scanners como opciones.
        self.fields["selected_scanners"].choices = [
            (entry["meta"].key, entry["meta"].label)
            for entry in SCANNER_REGISTRY
        ]

        # Por defecto: marcar los scanners con default=True.
        self.fields["selected_scanners"].initial = [
            entry["meta"].key
            for entry in SCANNER_REGISTRY
            if entry["meta"].default
        ]

    def clean_target_url(self) -> str:
        url = self.cleaned_data["target_url"]
        try:
            resolve_and_validate(url)
        except ValidationError:
            raise
        return url

    def clean_selected_scanners(self) -> list[str]:
        """
        Valida la selección de scanners contra el modo de escaneo.
        Los scanners de tier 'active' solo se permiten con scan_mode='active'.
        """
        selected = self.cleaned_data.get("selected_scanners", [])
        if not selected:
            return []

        scan_mode = self.cleaned_data.get("scan_mode", "passive")
        available = get_available_scanners(scan_mode)
        available_keys = {m.key for m in available}

        return [key for key in selected if key in available_keys]

    def save(self, commit=True):
        """Guardar la selección de scanners en el campo JSON del modelo."""
        audit = super().save(commit=False)
        audit.selected_scanners = self.cleaned_data.get("selected_scanners", [])
        if commit:
            audit.save()
        return audit
