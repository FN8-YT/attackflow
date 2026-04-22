"""URLs de la app users."""
from django.urls import path

from .views import RegisterView, dashboard

app_name = "users"

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("dashboard/", dashboard, name="dashboard"),
]
