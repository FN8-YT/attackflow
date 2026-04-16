#!/bin/sh
# entrypoint.sh — se ejecuta cada vez que el contenedor arranca.
# Corre migraciones y collectstatic antes de levantar Gunicorn.
set -e

echo "=== Running migrations ==="
python manage.py migrate --noinput

echo "=== Collecting static files ==="
python manage.py collectstatic --noinput --clear

echo "=== Bootstrap: verifying superusers & clearing axes lockouts ==="
python manage.py shell -c "
from apps.users.models import User
from axes.models import AccessAttempt

cleared = AccessAttempt.objects.all().delete()[0]
if cleared:
    print(f'  Axes: cleared {cleared} lockout(s)')

updated = User.objects.filter(is_superuser=True, is_verified=False).update(is_verified=True)
if updated:
    print(f'  Users: verified {updated} superuser(s)')
"

echo "=== Starting Gunicorn ==="
exec gunicorn config.wsgi:application \
    --bind "0.0.0.0:${PORT:-8000}" \
    --workers 2 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile -
