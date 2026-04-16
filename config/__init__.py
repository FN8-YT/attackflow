"""Proyecto Django de la plataforma de auditoría de seguridad."""

# Cargamos la app Celery cuando Django arranca, para que `@shared_task`
# funcione automáticamente en cualquier app instalada.
from .celery import app as celery_app

__all__ = ("celery_app",)
