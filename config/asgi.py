"""Punto de entrada ASGI (preparado para WebSockets/SSE en el futuro)."""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

application = get_asgi_application()
