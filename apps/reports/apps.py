from django.apps import AppConfig


class ReportsConfig(AppConfig):
    """Cálculo de scoring y generación de informes."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.reports"
    verbose_name = "Reports"
