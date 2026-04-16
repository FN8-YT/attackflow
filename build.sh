#!/usr/bin/env bash
# build.sh — Render lo ejecuta automáticamente antes de arrancar el servicio.
# Render ya instala las dependencias del Dockerfile; este script hace
# las operaciones de Django que necesitan la BD lista.
set -e

echo "=== Running migrations ==="
python manage.py migrate --noinput

echo "=== Collecting static files ==="
python manage.py collectstatic --noinput --clear

echo "=== Build complete ==="
