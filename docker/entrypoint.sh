#!/bin/sh
# entrypoint.sh — se ejecuta cada vez que el contenedor arranca.
# Corre migraciones y collectstatic antes de levantar Gunicorn.
set -e

echo "=== Running migrations ==="
python manage.py migrate --noinput

echo "=== Collecting static files ==="
python manage.py collectstatic --noinput --clear

echo "=== Starting Gunicorn ==="
exec gunicorn config.wsgi:application \
    --bind "0.0.0.0:${PORT:-8000}" \
    --workers 2 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile -
