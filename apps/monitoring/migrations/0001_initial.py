"""Initial migration for apps.monitoring."""
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="MonitorTarget",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(
                    help_text="Nombre amigable para identificar este target.",
                    max_length=128,
                    verbose_name="name",
                )),
                ("url", models.URLField(
                    help_text="URL completa a monitorizar (https://example.com).",
                    max_length=2048,
                    verbose_name="URL",
                )),
                ("is_active", models.BooleanField(default=True, verbose_name="active")),
                ("check_interval", models.IntegerField(
                    choices=[
                        (5, "Every 5 min (Premium)"),
                        (15, "Every 15 min"),
                        (30, "Every 30 min"),
                        (60, "Every hour"),
                        (360, "Every 6 hours"),
                        (1440, "Every 24 hours"),
                    ],
                    default=30,
                    help_text="Frecuencia de comprobación en minutos.",
                    verbose_name="check interval",
                )),
                ("current_status", models.CharField(
                    choices=[
                        ("unknown", "Unknown"),
                        ("up", "Online"),
                        ("down", "Offline"),
                        ("error", "Error"),
                    ],
                    db_index=True,
                    default="unknown",
                    max_length=16,
                    verbose_name="current status",
                )),
                ("last_check_at", models.DateTimeField(blank=True, null=True, verbose_name="last check at")),
                ("last_response_ms", models.IntegerField(blank=True, null=True, verbose_name="last response ms")),
                ("last_http_status", models.IntegerField(blank=True, null=True, verbose_name="last HTTP status")),
                ("last_ssl_days", models.IntegerField(blank=True, null=True, verbose_name="SSL days remaining")),
                ("consecutive_failures", models.PositiveSmallIntegerField(default=0)),
                ("uptime_pct", models.DecimalField(
                    blank=True,
                    decimal_places=2,
                    max_digits=5,
                    null=True,
                    verbose_name="uptime %",
                )),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="monitor_targets",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "verbose_name": "monitor target",
                "verbose_name_plural": "monitor targets",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="MonitorCheck",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("status", models.CharField(
                    choices=[("up", "Up"), ("down", "Down"), ("error", "Error")],
                    max_length=8,
                )),
                ("http_status_code", models.IntegerField(blank=True, null=True)),
                ("response_time_ms", models.IntegerField(blank=True, null=True)),
                ("ssl_expiry_days", models.IntegerField(blank=True, null=True)),
                ("ssl_issuer", models.CharField(blank=True, default="", max_length=256)),
                ("ssl_fingerprint", models.CharField(blank=True, default="", max_length=128)),
                ("headers_snapshot", models.JSONField(
                    blank=True,
                    default=dict,
                    help_text="Cabeceras de seguridad capturadas.",
                )),
                ("content_hash", models.CharField(blank=True, default="", max_length=64)),
                ("error_message", models.TextField(blank=True, default="")),
                ("target", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="checks",
                    to="monitoring.monitortarget",
                )),
            ],
            options={
                "verbose_name": "monitor check",
                "verbose_name_plural": "monitor checks",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="MonitorChange",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("change_type", models.CharField(
                    choices=[
                        ("status_down", "Target went OFFLINE"),
                        ("status_up", "Target came back ONLINE"),
                        ("http_status", "HTTP status code changed"),
                        ("header_added", "Security header added"),
                        ("header_removed", "Security header removed"),
                        ("header_changed", "Security header value changed"),
                        ("ssl_expiry_warn", "SSL certificate expiring soon"),
                        ("ssl_expiry_chg", "SSL certificate renewed/changed"),
                        ("content_changed", "Page content changed"),
                        ("response_slow", "Response time degraded"),
                    ],
                    max_length=24,
                )),
                ("severity", models.CharField(
                    choices=[
                        ("critical", "Critical"),
                        ("high", "High"),
                        ("medium", "Medium"),
                        ("low", "Low"),
                        ("info", "Info"),
                    ],
                    max_length=16,
                )),
                ("description", models.CharField(max_length=512)),
                ("old_value", models.TextField(blank=True, default="")),
                ("new_value", models.TextField(blank=True, default="")),
                ("monitor_check", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="changes",
                    to="monitoring.monitorcheck",
                )),
                ("target", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="changes",
                    to="monitoring.monitortarget",
                )),
            ],
            options={
                "verbose_name": "monitor change",
                "verbose_name_plural": "monitor changes",
                "ordering": ("-created_at",),
            },
        ),
        migrations.AddIndex(
            model_name="monitorcheck",
            index=models.Index(fields=["target", "-created_at"], name="monitoring__target__check_idx"),
        ),
        migrations.AddIndex(
            model_name="monitorchange",
            index=models.Index(fields=["target", "-created_at"], name="monitoring__target__change_idx"),
        ),
        migrations.AddIndex(
            model_name="monitorchange",
            index=models.Index(fields=["severity"], name="monitoring__severity_idx"),
        ),
    ]
