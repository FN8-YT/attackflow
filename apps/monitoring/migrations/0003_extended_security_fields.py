"""
Añade campos de análisis de seguridad extendido:

MonitorCheck:
  - technologies: stack tecnológico detectado
  - waf_detected: WAF/CDN detectado
  - sensitive_paths_found: paths sensibles expuestos
  - security_score: puntuación 0-100

MonitorTarget:
  - check_sensitive_paths: toggle para activar el escaneo de paths
  - last_security_score: score cacheado del último check
  - last_technologies: tecnologías del último check (caché)
  - last_waf: WAF del último check (caché)
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitoring", "0002_alter_monitorchange_created_at_and_more"),
    ]

    operations = [
        # ── MonitorCheck — nuevos campos ──────────────────────────────────
        migrations.AddField(
            model_name="monitorcheck",
            name="technologies",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Stack tecnológico detectado (servidor, lenguaje, frameworks, CMS).",
            ),
        ),
        migrations.AddField(
            model_name="monitorcheck",
            name="waf_detected",
            field=models.CharField(
                blank=True,
                default="",
                max_length=64,
                verbose_name="WAF/CDN",
            ),
        ),
        migrations.AddField(
            model_name="monitorcheck",
            name="sensitive_paths_found",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Paths sensibles que devolvieron un status HTTP != 404.",
            ),
        ),
        migrations.AddField(
            model_name="monitorcheck",
            name="security_score",
            field=models.IntegerField(
                blank=True,
                null=True,
                verbose_name="security score",
                help_text="Puntuación 0–100 de la postura de seguridad.",
            ),
        ),
        # ── MonitorTarget — nuevos campos ─────────────────────────────────
        migrations.AddField(
            model_name="monitortarget",
            name="check_sensitive_paths",
            field=models.BooleanField(
                default=True,
                verbose_name="scan sensitive paths",
                help_text=(
                    "Sondear paths sensibles (admin, .git, .env, etc.) "
                    "para detectar exposición de superficie de ataque."
                ),
            ),
        ),
        migrations.AddField(
            model_name="monitortarget",
            name="last_security_score",
            field=models.IntegerField(
                blank=True,
                null=True,
                verbose_name="last security score",
            ),
        ),
        migrations.AddField(
            model_name="monitortarget",
            name="last_technologies",
            field=models.JSONField(
                blank=True,
                default=list,
                verbose_name="last technologies",
            ),
        ),
        migrations.AddField(
            model_name="monitortarget",
            name="last_waf",
            field=models.CharField(
                blank=True,
                default="",
                max_length=64,
                verbose_name="last WAF/CDN",
            ),
        ),
    ]
