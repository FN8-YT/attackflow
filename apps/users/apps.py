from django.apps import AppConfig


class UsersConfig(AppConfig):
    """Cuentas de usuario, autenticación y planes."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
    verbose_name = "Users"
