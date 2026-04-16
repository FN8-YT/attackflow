"""URLs de la app audits."""
from django.urls import path

from . import views

app_name = "audits"

urlpatterns = [
    path("", views.audit_list, name="list"),
    path("new/", views.create_audit, name="create"),
    path("<int:pk>/", views.audit_detail, name="detail"),
    path("<int:pk>/status/", views.audit_status, name="status"),
    path("<int:pk>/status.json", views.audit_status_api, name="status_api"),
]
