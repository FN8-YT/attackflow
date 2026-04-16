"""
Modelos del dominio de auditoría.

Diseño:
- Audit: cabecera. Estado, usuario, URL, score y raw_data con los
  outputs crudos de cada scanner (JSONB en Postgres → consultas baratas).
- Finding: cada problema detectado. Pertenece a un Audit.
- Los enums son TextChoices (type-safe, filtrables en admin).
- raw_data permite re-puntuar históricos sin volver a escanear.
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from apps.core.models import TimeStampedModel


class AuditStatus(models.TextChoices):
    PENDING = "pending", _("Pending")
    RUNNING = "running", _("Running")
    COMPLETED = "completed", _("Completed")
    FAILED = "failed", _("Failed")


class Severity(models.TextChoices):
    INFO = "info", _("Info")
    LOW = "low", _("Low")
    MEDIUM = "medium", _("Medium")
    HIGH = "high", _("High")
    CRITICAL = "critical", _("Critical")


class ScanMode(models.TextChoices):
    PASSIVE = "passive", _("Passive")
    ACTIVE = "active", _("Active")


class Category(models.TextChoices):
    DNS = "dns", _("DNS")
    TRANSPORT = "transport", _("Transport / TLS")
    HEADERS = "headers", _("HTTP Headers")
    COOKIES = "cookies", _("Cookies")
    PORTS = "ports", _("Open Ports")
    VULNS = "vulns", _("Vulnerabilities")
    RECON = "recon", _("Reconnaissance")
    MISCONFIG = "misconfig", _("Misconfigurations")
    # OWASP Top 10 categories
    ACCESS = "access", _("Broken Access Control")
    CRYPTO = "crypto", _("Cryptographic Failures")
    DESIGN = "design", _("Insecure Design")
    COMPONENTS = "components", _("Vulnerable Components")
    AUTH = "auth", _("Authentication Failures")
    INTEGRITY = "integrity", _("Software Integrity")
    LOGGING = "logging", _("Logging & Monitoring")
    SSRF = "ssrf", _("SSRF")
    # JavaScript Client-Side Analysis
    JS = "js", _("JavaScript Analysis")


class Audit(TimeStampedModel):
    """Cabecera de una auditoría de seguridad."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="audits",
    )
    target_url = models.URLField(
        _("target URL"),
        max_length=2048,
        help_text=_("URL original enviada por el usuario."),
    )
    normalized_host = models.CharField(
        _("hostname"),
        max_length=253,
        blank=True,
        help_text=_("Hostname extraído tras validar la URL."),
    )
    status = models.CharField(
        _("status"),
        max_length=16,
        choices=AuditStatus.choices,
        default=AuditStatus.PENDING,
        db_index=True,
    )
    score = models.PositiveSmallIntegerField(
        _("score"),
        null=True,
        blank=True,
        help_text=_("Puntuación 0-100 calculada al finalizar."),
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, default="")
    scan_mode = models.CharField(
        _("scan mode"),
        max_length=16,
        choices=ScanMode.choices,
        default=ScanMode.PASSIVE,
        help_text=_("Pasivo = solo observa. Activo = envía payloads de prueba."),
    )
    selected_scanners = models.JSONField(
        _("selected scanners"),
        default=list,
        blank=True,
        help_text=_(
            "Lista de scanner keys seleccionados por el usuario. "
            "Vacío = ejecutar todos los disponibles según plan y modo."
        ),
    )
    raw_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Outputs crudos de cada scanner para debug y re-scoring."),
    )

    class Meta:
        verbose_name = _("audit")
        verbose_name_plural = _("audits")
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"Audit #{self.pk} · {self.target_url} [{self.status}]"

    def get_absolute_url(self) -> str:
        return reverse("audits:detail", kwargs={"pk": self.pk})

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class Finding(TimeStampedModel):
    """Un hallazgo concreto dentro de una auditoría."""

    audit = models.ForeignKey(
        Audit,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    category = models.CharField(
        _("category"),
        max_length=16,
        choices=Category.choices,
        db_index=True,
    )
    severity = models.CharField(
        _("severity"),
        max_length=16,
        choices=Severity.choices,
        db_index=True,
    )
    title = models.CharField(_("title"), max_length=255)
    description = models.TextField(_("description"))
    evidence = models.JSONField(
        _("evidence"),
        default=dict,
        blank=True,
        help_text=_("Datos concretos que soportan el hallazgo."),
    )
    recommendation = models.TextField(_("recommendation"), blank=True, default="")
    reference_url = models.URLField(_("reference URL"), blank=True, default="")

    # Orden de severidad para que el templating no tenga que saberlo.
    _SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    class Meta:
        verbose_name = _("finding")
        verbose_name_plural = _("findings")
        ordering = ("severity",)
        indexes = [
            models.Index(fields=["audit", "severity"]),
        ]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"
