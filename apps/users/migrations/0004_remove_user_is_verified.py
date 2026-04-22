"""
Elimina el campo `is_verified` del modelo User.

No hay verificación de email: el registro da acceso inmediato.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0003_remove_user_plan"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="user",
            name="is_verified",
        ),
    ]
