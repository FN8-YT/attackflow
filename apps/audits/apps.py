from django.apps import AppConfig


class AuditsConfig(AppConfig):
    """Modelo Audit, scanners y orquestación de tareas."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.audits"
    verbose_name = "Audits"
