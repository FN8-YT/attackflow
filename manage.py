#!/usr/bin/env python
"""Punto de entrada de comandos administrativos de Django."""
import os
import sys


def main() -> None:
    # Por defecto cargamos los settings de desarrollo.
    # En producción esta variable se inyecta vía entorno y este default no aplica.
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "No se pudo importar Django. ¿Está instalado y la venv activada?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
