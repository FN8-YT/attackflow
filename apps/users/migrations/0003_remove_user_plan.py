"""
Elimina el campo `plan` del modelo User.

AttackFlow es completamente gratuito: no existe sistema de planes.
Todos los usuarios tienen acceso total a todas las funcionalidades.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_user_is_verified"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="user",
            name="plan",
        ),
    ]
