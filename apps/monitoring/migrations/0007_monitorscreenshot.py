"""
Añade MonitorScreenshot — capturas de pantalla para visual monitoring.
"""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("monitoring", "0006_monitorsubdomain_last_deep_check_at"),
    ]

    operations = [
        migrations.CreateModel(
            name="MonitorScreenshot",
            fields=[
                ("id",                   models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at",           models.DateTimeField(auto_now_add=True)),
                ("updated_at",           models.DateTimeField(auto_now=True)),
                ("image_b64",            models.TextField(blank=True, default="", help_text="PNG de la página codificado en base64.", verbose_name="screenshot base64")),
                ("image_hash",           models.CharField(blank=True, default="", help_text="SHA-256 truncado del screenshot.", max_length=32, verbose_name="image hash")),
                ("diff_pct",             models.FloatField(blank=True, help_text="% de píxeles que cambiaron.", null=True, verbose_name="pixel diff %")),
                ("is_defacement_alert",  models.BooleanField(default=False, help_text="True si diff supera el umbral.", verbose_name="defacement alert")),
                ("width",                models.IntegerField(default=1280, verbose_name="width")),
                ("height",               models.IntegerField(default=800, verbose_name="height")),
                ("monitor_check",        models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="screenshots", to="monitoring.monitorcheck")),
            ],
            options={
                "verbose_name":        "monitor screenshot",
                "verbose_name_plural": "monitor screenshots",
                "ordering":            ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="monitorscreenshot",
            index=models.Index(fields=["monitor_check"], name="mon_screenshot_check_idx"),
        ),
    ]
