"""URLs de la app users."""
from django.urls import path

from .views import (
    RegisterView,
    dashboard,
    plans,
    verify_email_link,
    verify_pending,
    resend_verification,
)

app_name = "users"

urlpatterns = [
    # Registro y autenticación
    path("register/", RegisterView.as_view(), name="register"),
    path("dashboard/", dashboard, name="dashboard"),
    path("plans/", plans, name="plans"),

    # Verificación de email.
    # Viven bajo /accounts/ (montado en config/urls.py) → el middleware
    # los exime automáticamente por el prefijo "/accounts/".
    path("verify/", verify_pending, name="verify_pending"),
    path("verify/resend/", resend_verification, name="resend_verification"),
    path("verify/<str:token>/", verify_email_link, name="verify_email"),
]
