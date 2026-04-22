"""URLs para Continuous Monitoring."""
from django.urls import path

from . import views

app_name = "monitoring"

urlpatterns = [
    path("",                         views.monitor_dashboard,    name="dashboard"),
    path("add/",                     views.monitor_add,          name="add"),
    path("<int:pk>/",                views.monitor_detail,       name="detail"),
    path("<int:pk>/delete/",         views.monitor_delete,       name="delete"),
    path("<int:pk>/toggle/",         views.monitor_toggle,       name="toggle"),
    path("<int:pk>/run/",            views.monitor_run_now,      name="run_now"),
    path("<int:pk>/status.json/",    views.monitor_status_json,  name="status_json"),
    path("<int:pk>/history.json/",   views.monitor_history_json, name="history_json"),
    path("<int:pk>/checks.json/",      views.monitor_checks_json,     name="checks_json"),
    path("<int:pk>/surface.json/",     views.monitor_surface_json,    name="surface_json"),
    path("<int:pk>/screenshot.json/",  views.monitor_screenshot_json, name="screenshot_json"),
]
