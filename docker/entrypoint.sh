#!/bin/sh
# entrypoint.sh — se ejecuta cada vez que el contenedor arranca.
# Corre migraciones y collectstatic antes de levantar Gunicorn.
set -e

echo "=== Running migrations ==="
python manage.py migrate --noinput

echo "=== Collecting static files ==="
python manage.py collectstatic --noinput --clear

echo "=== Bootstrap: superuser + axes ==="
python manage.py shell -c "
from apps.users.models import User
from axes.models import AccessAttempt

# Limpia bloqueos de axes
cleared = AccessAttempt.objects.all().delete()[0]
if cleared:
    print(f'  Axes: cleared {cleared} lockout(s)')

# Crea superusuario si no existe
email = 'santiagopenarandamejia82@gmail.com'
if not User.objects.filter(email=email).exists():
    u = User.objects.create_superuser(email=email, password='santo')
    u.plan = 'admin'
    u.save(update_fields=['plan'])
    print(f'  Superuser created: {email} (plan=admin)')
else:
    u = User.objects.get(email=email)
    u.is_superuser = True
    u.is_staff = True
    u.is_verified = True
    u.plan = 'admin'
    u.set_password('santo')
    u.save()
    print(f'  Superuser updated: {email} (plan=admin)')
"

echo "=== Starting Gunicorn ==="
exec gunicorn config.wsgi:application \
    --bind "0.0.0.0:${PORT:-8000}" \
    --workers 1 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -
