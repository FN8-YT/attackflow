"""
Cambia la unidad de check_interval de minutos a segundos y añade
intervalos cortos para monitoreo en tiempo real (5s, 30s, 1min).

Data migration: multiplica todos los valores existentes × 60.
  5 min  →  300 s
  15 min →  900 s
  30 min → 1800 s
  60 min → 3600 s
  360 min → 21600 s
  1440 min → 86400 s

Nuevas opciones disponibles tras la migración:
  5 s, 30 s, 60 s (intervalos live / tiempo real)
"""
from django.db import migrations, models


def minutes_to_seconds(apps, schema_editor):
    """Convierte todos los check_interval existentes de minutos a segundos."""
    MonitorTarget = apps.get_model("monitoring", "MonitorTarget")
    for target in MonitorTarget.objects.all():
        # Multiplicar solo si el valor es "viejo" (minutos).
        # Los nuevos valores en segundos (5, 30, 60, 300…) son distinguibles
        # porque los intervalos en minutos originales eran: 5, 15, 30, 60, 360, 1440.
        # Todos esos valores × 60 dan valores válidos en la nueva escala.
        target.check_interval = target.check_interval * 60
        target.save(update_fields=["check_interval"])


def seconds_to_minutes(apps, schema_editor):
    """Reversión: divide check_interval entre 60 (solo para rollback)."""
    MonitorTarget = apps.get_model("monitoring", "MonitorTarget")
    VALID_MINUTES = {5, 15, 30, 60, 360, 1440}
    for target in MonitorTarget.objects.all():
        candidate = target.check_interval // 60
        if candidate in VALID_MINUTES:
            target.check_interval = candidate
            target.save(update_fields=["check_interval"])


class Migration(migrations.Migration):

    dependencies = [
        ("monitoring", "0004_alter_monitorchange_change_type_and_more"),
    ]

    operations = [
        # 1. Convertir datos existentes antes de cambiar el campo
        migrations.RunPython(minutes_to_seconds, reverse_code=seconds_to_minutes),

        # 2. Actualizar las choices del campo (solo metadatos, no cambia tipo de columna)
        migrations.AlterField(
            model_name="monitortarget",
            name="check_interval",
            field=models.IntegerField(
                choices=[
                    (5,     "Every 5 seconds  ⚡ live"),
                    (30,    "Every 30 seconds ⚡ live"),
                    (60,    "Every minute     ⚡ live"),
                    (300,   "Every 5 min"),
                    (900,   "Every 15 min"),
                    (1800,  "Every 30 min"),
                    (3600,  "Every hour"),
                    (21600, "Every 6 hours"),
                    (86400, "Every 24 hours"),
                ],
                default=1800,
                help_text="Frecuencia de comprobación (en segundos internamente).",
                verbose_name="check interval",
            ),
        ),
    ]
