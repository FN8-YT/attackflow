from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Utilidades transversales: modelos base, mixins, validadores."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    verbose_name = "Core"
