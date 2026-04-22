"""WebSocket URL routing para Monitoring."""
from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path("ws/monitoring/<int:pk>/",  consumers.MonitorDetailConsumer.as_asgi()),
    path("ws/monitoring/dashboard/", consumers.DashboardConsumer.as_asgi()),
]
