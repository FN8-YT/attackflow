"""
Añade el campo is_verified al modelo User.

RunPython:
  Los usuarios existentes se marcan automáticamente como verificados
  (is_verified=True) porque ya superaron el proceso de registro antes
  de que se introdujera esta feature. No queremos bloquear cuentas activas.
  Los usuarios nuevos recibirán is_verified=False (valor por defecto del campo).
"""
from django.db import migrations, models


def verify_existing_users(apps, schema_editor):
    """Marca todos los usuarios actuales como verificados."""
    User = apps.get_model("users", "User")
    User.objects.all().update(is_verified=True)


def unverify_existing_users(apps, schema_editor):
    """Rollback: deja el campo a False (aunque ya no existirá si se revierte)."""
    pass  # No necesitamos hacer nada en el rollback


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="is_verified",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Indica si el usuario ha confirmado su dirección de email. "
                    "Los usuarios no verificados no pueden acceder a la plataforma."
                ),
                verbose_name="email verified",
            ),
        ),
        # Verificar usuarios existentes DESPUÉS de añadir el campo.
        migrations.RunPython(
            verify_existing_users,
            reverse_code=unverify_existing_users,
        ),
    ]
