"""
Bootstrap de Celery.

Patrón estándar:
1. Cargar settings de Django antes de instanciar la app.
2. Leer config con prefijo CELERY_ del módulo de settings.
3. Autodescubrir tasks.py en cada app instalada.
"""
import os

from celery import Celery

# Default razonable; en prod se sobrescribe vía entorno.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

app = Celery("securityaudit")

# Toda la config de Celery vive en el settings de Django con prefijo CELERY_.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Busca automáticamente `tasks.py` en cada app instalada.
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self) -> None:
    """Tarea de prueba para verificar que el worker arranca."""
    print(f"Request: {self.request!r}")
