#!/usr/bin/env bash
# =========================================================
# generate_cert.sh — Certificado TLS autofirmado para testing
#
# Uso:
#   chmod +x nginx/generate_cert.sh
#   ./nginx/generate_cert.sh
#
# Genera nginx/certs/fullchain.pem y nginx/certs/privkey.pem
# válidos por 1 año.
#
# Para producción real usa Let's Encrypt:
#   certbot certonly --webroot -w /var/www/certbot -d tudominio.com
#   # Luego copia los archivos a nginx/certs/
# =========================================================
set -euo pipefail

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "${CERTS_DIR}/privkey.pem" \
  -out    "${CERTS_DIR}/fullchain.pem" \
  -subj   "/C=ES/ST=Madrid/L=Madrid/O=AttackFlow/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "✓ Certificado autofirmado generado en ${CERTS_DIR}/"
echo "  fullchain.pem  $(wc -l < "${CERTS_DIR}/fullchain.pem") líneas"
echo "  privkey.pem    $(wc -l < "${CERTS_DIR}/privkey.pem") líneas"
echo ""
echo "⚠ Este certificado es SOLO para testing."
echo "  Para producción: certbot certonly --webroot ..."
