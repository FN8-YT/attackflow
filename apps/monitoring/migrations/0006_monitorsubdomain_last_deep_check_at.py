"""
Añade:
  - MonitorTarget.last_deep_check_at  — timestamp del último deep check (subdomains + paths)
  - MonitorSubdomain                  — subdominios descubiertos por el scanner
"""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("monitoring", "0005_check_interval_to_seconds"),
    ]

    operations = [
        # 1. Campo last_deep_check_at en MonitorTarget
        migrations.AddField(
            model_name="monitortarget",
            name="last_deep_check_at",
            field=models.DateTimeField(
                blank=True,
                help_text="Última vez que se ejecutó el deep check: subdominios + sensitive paths (cada 6h).",
                null=True,
                verbose_name="last deep check at",
            ),
        ),

        # 2. Modelo MonitorSubdomain
        migrations.CreateModel(
            name="MonitorSubdomain",
            fields=[
                ("id",               models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at",       models.DateTimeField(auto_now_add=True)),
                ("updated_at",       models.DateTimeField(auto_now=True)),
                ("hostname",         models.CharField(help_text="FQDN completo: api.example.com", max_length=512, verbose_name="hostname")),
                ("subdomain",        models.CharField(help_text="Prefijo del subdominio: api", max_length=128, verbose_name="subdomain prefix")),
                ("ip_address",       models.CharField(blank=True, default="", max_length=64, verbose_name="IP address")),
                ("is_active",        models.BooleanField(default=True, help_text="True si el subdominio respondió en el último deep check.", verbose_name="active")),
                ("http_status_code", models.IntegerField(blank=True, null=True, verbose_name="HTTP status")),
                ("response_time_ms", models.IntegerField(blank=True, null=True, verbose_name="response time ms")),
                ("last_seen_at",     models.DateTimeField(blank=True, help_text="Última vez que el subdominio estuvo activo.", null=True, verbose_name="last seen at")),
                ("target",           models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="subdomains", to="monitoring.monitortarget")),
            ],
            options={
                "verbose_name":        "monitor subdomain",
                "verbose_name_plural": "monitor subdomains",
                "ordering":            ["-is_active", "hostname"],
            },
        ),

        # 3. unique_together e índice
        migrations.AlterUniqueTogether(
            name="monitorsubdomain",
            unique_together={("target", "hostname")},
        ),
        migrations.AddIndex(
            model_name="monitorsubdomain",
            index=models.Index(
                fields=["target", "-is_active"],
                name="mon_subdomain_target_idx",
            ),
        ),
    ]
