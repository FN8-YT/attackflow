"""
Modelos de Continuous Monitoring.

Diseño:
- MonitorTarget: objetivo que el usuario monitoriza. Cachea el estado
  actual para evitar JOINs en el dashboard.
- MonitorCheck: resultado de una comprobación individual. Almacena
  uptime, headers, SSL, tecnologías detectadas, WAF, paths sensibles
  y puntuación de seguridad.
- MonitorChange: cambio detectado entre dos checks consecutivos.

Los campos cacheados en MonitorTarget (current_status, last_*) se
actualizan al finalizar cada check vía _update_target_status().
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from apps.core.models import TimeStampedModel


class CheckInterval(models.IntegerChoices):
    # Intervalos en SEGUNDOS (campo almacena segundos desde la migración 0005)
    SEC_5   = 5,     _("Every 5 seconds  ⚡ live")
    SEC_30  = 30,    _("Every 30 seconds ⚡ live")
    MIN_1   = 60,    _("Every minute     ⚡ live")
    MIN_5   = 300,   _("Every 5 min")
    MIN_15  = 900,   _("Every 15 min")
    MIN_30  = 1800,  _("Every 30 min")
    HOUR_1  = 3600,  _("Every hour")
    HOUR_6  = 21600, _("Every 6 hours")
    HOUR_24 = 86400, _("Every 24 hours")


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
    # Uptime
    STATUS_DOWN     = "status_down",     _("Target went OFFLINE")
    STATUS_UP       = "status_up",       _("Target came back ONLINE")
    # HTTP
    HTTP_STATUS     = "http_status",     _("HTTP status code changed")
    RESPONSE_SLOW   = "response_slow",   _("Response time degraded")
    REDIRECT_CHANGE = "redirect_change", _("Redirect chain changed")
    # Security headers
    HEADER_ADDED    = "header_added",    _("Security header added")
    HEADER_REMOVED  = "header_removed",  _("Security header removed")
    HEADER_CHANGED  = "header_changed",  _("Security header value changed")
    # SSL
    SSL_EXPIRY_WARN = "ssl_expiry_warn", _("SSL certificate expiring soon")
    SSL_EXPIRY_CHG  = "ssl_expiry_chg",  _("SSL certificate renewed/changed")
    # Content
    CONTENT_CHANGED = "content_changed", _("Page content changed")
    # Tech detection
    TECH_ADDED      = "tech_added",      _("Technology detected")
    TECH_REMOVED    = "tech_removed",    _("Technology removed")
    # WAF / CDN
    WAF_APPEARED    = "waf_appeared",    _("WAF/CDN appeared")
    WAF_GONE        = "waf_gone",        _("WAF/CDN disappeared")
    # Attack surface
    SENSITIVE_PATH  = "sensitive_path",  _("Sensitive path exposed")
    SCORE_DROP      = "score_drop",      _("Security score dropped")


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
        help_text=_("Frecuencia de comprobación (en segundos internamente)."),
    )
    check_sensitive_paths = models.BooleanField(
        _("scan sensitive paths"),
        default=True,
        help_text=_(
            "Sondear paths sensibles (admin, .git, .env, etc.) "
            "para detectar exposición de superficie de ataque."
        ),
    )

    # ── Estado cacheado (actualizado en cada check) ──────────────────────
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

    # ── Cached security analysis ─────────────────────────────────────────
    last_security_score = models.IntegerField(
        _("last security score"), null=True, blank=True,
    )
    last_technologies = models.JSONField(
        _("last technologies"), default=list, blank=True,
    )
    last_waf = models.CharField(
        _("last WAF/CDN"), max_length=64, blank=True, default="",
    )

    # ── Deep check tracking ───────────────────────────────────────────────
    last_deep_check_at = models.DateTimeField(
        _("last deep check at"),
        null=True, blank=True,
        help_text=_(
            "Última vez que se ejecutó el deep check: "
            "subdominios + sensitive paths (cada 6h)."
        ),
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
        import datetime
        from django.utils import timezone
        # check_interval está en SEGUNDOS (migración 0005)
        return timezone.now() >= self.last_check_at + datetime.timedelta(seconds=self.check_interval)

    @property
    def is_live(self) -> bool:
        """True para intervalos cortos (≤ 60s) — modo real-time."""
        return self.check_interval <= 60

    @property
    def interval_display(self) -> str:
        """Representación legible del intervalo."""
        s = self.check_interval
        if s < 60:
            return f"{s}s"
        elif s < 3600:
            m = s // 60
            return f"{m}m"
        else:
            h = s // 3600
            return f"{h}h"

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
        import datetime
        from django.utils import timezone
        since = timezone.now() - datetime.timedelta(hours=24)
        return self.changes.filter(created_at__gte=since).count()

    @property
    def security_grade(self) -> str:
        """Letra de grado del security score (A/B/C/D/F o '?')."""
        if self.last_security_score is None:
            return "?"
        from apps.monitoring.checks.scoring import score_grade
        grade, _ = score_grade(self.last_security_score)
        return grade


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

    # ── SSL ──────────────────────────────────────────────────────────────
    ssl_expiry_days = models.IntegerField(null=True, blank=True)
    ssl_issuer = models.CharField(max_length=256, blank=True, default="")
    ssl_fingerprint = models.CharField(max_length=128, blank=True, default="")

    # ── Snapshots para diff ───────────────────────────────────────────────
    headers_snapshot = models.JSONField(
        default=dict, blank=True,
        help_text=_("Security headers capturados en este check."),
    )
    content_hash = models.CharField(max_length=64, blank=True, default="")

    # ── Security analysis (nuevo) ─────────────────────────────────────────
    technologies = models.JSONField(
        default=list, blank=True,
        help_text=_("Stack tecnológico detectado (servidor, lenguaje, frameworks, CMS)."),
    )
    waf_detected = models.CharField(
        _("WAF/CDN"), max_length=64, blank=True, default="",
        help_text=_("WAF o CDN detectado en los response headers."),
    )
    sensitive_paths_found = models.JSONField(
        default=list, blank=True,
        help_text=_("Paths sensibles que devolvieron un status HTTP != 404."),
    )
    security_score = models.IntegerField(
        _("security score"), null=True, blank=True,
        help_text=_("Puntuación 0-100 de la postura de seguridad."),
    )

    # ── Error info ────────────────────────────────────────────────────────
    error_message = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = _("monitor check")
        verbose_name_plural = _("monitor checks")
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["target", "-created_at"], name="monitoring__target__check_idx"),
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
            models.Index(fields=["target", "-created_at"], name="monitoring__target__change_idx"),
            models.Index(fields=["severity"],               name="monitoring__severity_idx"),
        ]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.description}"


class MonitorSubdomain(TimeStampedModel):
    """
    Un subdominio descubierto durante el deep check de un MonitorTarget.

    Se actualiza con update_or_create en cada deep check. Si el subdominio
    dejó de responder, is_active pasa a False pero el registro se conserva
    para historial.
    """

    target = models.ForeignKey(
        MonitorTarget,
        on_delete=models.CASCADE,
        related_name="subdomains",
    )
    hostname = models.CharField(
        _("hostname"), max_length=512,
        help_text=_("FQDN completo: api.example.com"),
    )
    subdomain = models.CharField(
        _("subdomain prefix"), max_length=128,
        help_text=_("Prefijo del subdominio: api"),
    )
    ip_address = models.CharField(
        _("IP address"), max_length=64, blank=True, default="",
    )
    is_active = models.BooleanField(
        _("active"), default=True,
        help_text=_("True si el subdominio respondió en el último deep check."),
    )
    http_status_code = models.IntegerField(
        _("HTTP status"), null=True, blank=True,
    )
    response_time_ms = models.IntegerField(
        _("response time ms"), null=True, blank=True,
    )
    last_seen_at = models.DateTimeField(
        _("last seen at"), null=True, blank=True,
        help_text=_("Última vez que el subdominio estuvo activo."),
    )

    class Meta:
        verbose_name = _("monitor subdomain")
        verbose_name_plural = _("monitor subdomains")
        ordering = ("-is_active", "hostname")
        unique_together = [("target", "hostname")]
        indexes = [
            models.Index(
                fields=["target", "-is_active"],
                name="mon_subdomain_target_idx",
            ),
        ]

    def __str__(self) -> str:
        status = "active" if self.is_active else "inactive"
        return f"{self.hostname} [{status}]"


class MonitorScreenshot(TimeStampedModel):
    """
    Captura de pantalla visual del MonitorTarget tomada durante el deep check.

    Almacena el PNG como base64 en DB para evitar complejidad de media files.
    El diff_pct compara con el screenshot anterior para detectar defacements.
    """

    monitor_check = models.ForeignKey(
        MonitorCheck,
        on_delete=models.CASCADE,
        related_name="screenshots",
    )
    # Base64 PNG — ~100-500KB por screenshot
    image_b64 = models.TextField(
        _("screenshot base64"),
        blank=True, default="",
        help_text=_("PNG de la página codificado en base64."),
    )
    image_hash = models.CharField(
        _("image hash"), max_length=32, blank=True, default="",
        help_text=_("SHA-256 truncado del screenshot para detección rápida de cambios."),
    )
    diff_pct = models.FloatField(
        _("pixel diff %"), null=True, blank=True,
        help_text=_("Porcentaje de píxeles que cambiaron respecto al screenshot anterior."),
    )
    is_defacement_alert = models.BooleanField(
        _("defacement alert"), default=False,
        help_text=_("True si diff_pct supera el umbral de defacement (30%)."),
    )
    width  = models.IntegerField(_("width"),  default=1280)
    height = models.IntegerField(_("height"), default=800)

    class Meta:
        verbose_name = _("monitor screenshot")
        verbose_name_plural = _("monitor screenshots")
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=["monitor_check"],
                name="mon_screenshot_check_idx",
            ),
        ]

    def __str__(self) -> str:
        alert = " ⚠ DEFACEMENT" if self.is_defacement_alert else ""
        return f"Screenshot #{self.pk} · {self.monitor_check.target.name}{alert}"
