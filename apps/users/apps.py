from django.apps import AppConfig


class UsersConfig(AppConfig):
    """Cuentas de usuario y autenticación."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
    verbose_name = "Users"
