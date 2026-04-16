#!/bin/bash
# =========================================================
# deploy.sh — Script de despliegue de AttackFlow en producción
#
# Uso en el VPS:
#   chmod +x deploy.sh
#   ./deploy.sh
#
# Qué hace:
#   1. Pull de la imagen más reciente desde el registry (o rebuild local)
#   2. Ejecuta migraciones y collectstatic
#   3. Reinicia web, worker y beat sin downtime
# =========================================================

set -e   # Salir si cualquier comando falla
set -u   # Tratar variables no definidas como error

COMPOSE="docker compose -f docker-compose.prod.yml"

echo ""
echo "=== AttackFlow — Deploy $(date '+%Y-%m-%d %H:%M:%S') ==="
echo ""

# 1. Rebuild de imágenes (solo las capas que cambiaron)
echo ">> Building images..."
$COMPOSE build --no-cache

# 2. Arrancar servicios de infraestructura primero
echo ">> Starting db and redis..."
$COMPOSE up -d db redis

echo ">> Waiting for db to be healthy..."
sleep 5

# 3. Migrar y collectstatic
echo ">> Running migrations and collectstatic..."
$COMPOSE run --rm migrate

# 4. Recrear los servicios de aplicación (zero-downtime aproximado)
echo ">> Restarting app services..."
$COMPOSE up -d --no-deps web worker beat nginx

# 5. Limpieza de imágenes antiguas
echo ">> Cleaning old images..."
docker image prune -f

echo ""
echo "=== Deploy completado ==="
echo "Web: http://$(hostname -I | awk '{print $1}')"
echo "Logs: docker compose -f docker-compose.prod.yml logs -f web"
echo ""
