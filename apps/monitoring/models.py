"""
Modelos de Continuous Monitoring.

Diseño:
- MonitorTarget: un objetivo que el usuario quiere monitorizar.
- MonitorCheck: el resultado de una comprobación individual.
- MonitorChange: un cambio detectado al comparar dos checks consecutivos.

El status del target se cachea en el propio target para evitar JOIN
en el dashboard. Se actualiza al finalizar cada check.
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from apps.core.models import TimeStampedModel


class CheckInterval(models.IntegerChoices):
    MIN_5  = 5,    _("Every 5 min (Premium)")
    MIN_15 = 15,   _("Every 15 min")
    MIN_30 = 30,   _("Every 30 min")
    HOUR_1 = 60,   _("Every hour")
    HOUR_6 = 360,  _("Every 6 hours")
    HOUR_24 = 1440, _("Every 24 hours")


class TargetStatus(models.TextChoices):
    UNKNOWN = "unknown", _("Unknown")
    UP      = "up",      _("Online")
    DOWN    = "down",    _("Offline")
    ERROR   = "error",   _("Error")


class CheckStatus(models.TextChoices):
    UP    = "up",    _("Up")
    DOWN  = "down",  _("Down")
    ERROR = "error", _("Error")


class ChangeSeverity(models.TextChoices):
    CRITICAL = "critical", _("Critical")
    HIGH     = "high",     _("High")
    MEDIUM   = "medium",   _("Medium")
    LOW      = "low",      _("Low")
    INFO     = "info",     _("Info")


class ChangeType(models.TextChoices):
    STATUS_DOWN     = "status_down",     _("Target went OFFLINE")
    STATUS_UP       = "status_up",       _("Target came back ONLINE")
    HTTP_STATUS     = "http_status",     _("HTTP status code changed")
    HEADER_ADDED    = "header_added",    _("Security header added")
    HEADER_REMOVED  = "header_removed",  _("Security header removed")
    HEADER_CHANGED  = "header_changed",  _("Security header value changed")
    SSL_EXPIRY_WARN = "ssl_expiry_warn", _("SSL certificate expiring soon")
    SSL_EXPIRY_CHG  = "ssl_expiry_chg",  _("SSL certificate renewed/changed")
    CONTENT_CHANGED = "content_changed", _("Page content changed")
    RESPONSE_SLOW   = "response_slow",   _("Response time degraded")


class MonitorTarget(TimeStampedModel):
    """Un objetivo que el usuario monitoriza de forma continua."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="monitor_targets",
    )
    name = models.CharField(
        _("name"), max_length=128,
        help_text=_("Nombre amigable para identificar este target."),
    )
    url = models.URLField(
        _("URL"), max_length=2048,
        help_text=_("URL completa a monitorizar (https://example.com)."),
    )
    is_active = models.BooleanField(_("active"), default=True)
    check_interval = models.IntegerField(
        _("check interval"),
        choices=CheckInterval.choices,
        default=CheckInterval.MIN_30,
        help_text=_("Frecuencia de comprobación en minutos."),
    )

    # Estado cacheado (actualizado en cada check para rapidez en listado).
    current_status = models.CharField(
        _("current status"),
        max_length=16,
        choices=TargetStatus.choices,
        default=TargetStatus.UNKNOWN,
        db_index=True,
    )
    last_check_at = models.DateTimeField(_("last check at"), null=True, blank=True)
    last_response_ms = models.IntegerField(_("last response ms"), null=True, blank=True)
    last_http_status = models.IntegerField(_("last HTTP status"), null=True, blank=True)
    last_ssl_days = models.IntegerField(_("SSL days remaining"), null=True, blank=True)
    consecutive_failures = models.PositiveSmallIntegerField(default=0)
    uptime_pct = models.DecimalField(
        _("uptime %"), max_digits=5, decimal_places=2, null=True, blank=True,
    )

    class Meta:
        verbose_name = _("monitor target")
        verbose_name_plural = _("monitor targets")
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"{self.name} ({self.url})"

    def get_absolute_url(self) -> str:
        return reverse("monitoring:detail", kwargs={"pk": self.pk})

    @property
    def is_due(self) -> bool:
        """True si es hora de ejecutar el siguiente check."""
        if not self.last_check_at:
            return True
        from django.utils import timezone
        import datetime
        delta = datetime.timedelta(minutes=self.check_interval)
        return timezone.now() >= self.last_check_at + delta

    @property
    def status_color(self) -> str:
        return {
            "up":      "green",
            "down":    "red",
            "error":   "amber",
            "unknown": "gray",
        }.get(self.current_status, "gray")

    @property
    def recent_changes_count(self) -> int:
        from django.utils import timezone
        import datetime
        since = timezone.now() - datetime.timedelta(hours=24)
        return self.changes.filter(created_at__gte=since).count()


class MonitorCheck(TimeStampedModel):
    """Resultado de una comprobación individual de un target."""

    target = models.ForeignKey(
        MonitorTarget,
        on_delete=models.CASCADE,
        related_name="checks",
    )
    status = models.CharField(
        max_length=8, choices=CheckStatus.choices,
    )
    http_status_code = models.IntegerField(null=True, blank=True)
    response_time_ms = models.IntegerField(null=True, blank=True)

    # SSL
    ssl_expiry_days = models.IntegerField(null=True, blank=True)
    ssl_issuer = models.CharField(max_length=256, blank=True, default="")
    ssl_fingerprint = models.CharField(max_length=128, blank=True, default="")

    # Snapshots para diff
    headers_snapshot = models.JSONField(
        default=dict, blank=True,
        help_text=_("Cabeceras de seguridad capturadas."),
    )
    content_hash = models.CharField(max_length=64, blank=True, default="")

    # Error info
    error_message = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = _("monitor check")
        verbose_name_plural = _("monitor checks")
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["target", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"Check #{self.pk} · {self.target.name} [{self.status}]"


class MonitorChange(TimeStampedModel):
    """Un cambio detectado entre dos checks consecutivos."""

    target = models.ForeignKey(
        MonitorTarget,
        on_delete=models.CASCADE,
        related_name="changes",
    )
    monitor_check = models.ForeignKey(
        MonitorCheck,
        on_delete=models.CASCADE,
        related_name="changes",
    )
    change_type = models.CharField(
        max_length=24, choices=ChangeType.choices,
    )
    severity = models.CharField(
        max_length=16, choices=ChangeSeverity.choices,
    )
    description = models.CharField(max_length=512)
    old_value = models.TextField(blank=True, default="")
    new_value = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = _("monitor change")
        verbose_name_plural = _("monitor changes")
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["target", "-created_at"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.description}"
