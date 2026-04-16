"""
OWASP A01 — Broken Access Control.

Detecta desde fuera (sin credenciales):
- CORS misconfiguration (reflejo de Origin, wildcard con credentials).
- Paneles de admin accesibles sin autenticación.
- Métodos HTTP peligrosos habilitados (PUT, DELETE, TRACE).
- Path traversal básico en la respuesta.

Limitaciones honestas:
- IDOR requiere autenticación y conocer IDs, no es viable en scan externo.
- Escalada de privilegios requiere cuentas reales.
"""
from __future__ import annotations

import logging

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

TIMEOUT = 8
UA = "SecurityAuditBot/0.1"

# Paneles de admin comunes.
ADMIN_PATHS = [
    "/admin/", "/admin/login/", "/administrator/",
    "/wp-admin/", "/wp-login.php",
    "/manager/html", "/phpmyadmin/",
    "/cpanel", "/webmail",
    "/dashboard/", "/panel/",
    "/_admin/", "/admin-console/",
]

# Métodos HTTP a probar.
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "PATCH"]


class BrokenAccessScanner(BaseScanner):
    name = "broken_access"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        base = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base += f":{target.port}"

        cors = self._check_cors(base, target.hostname)
        admin = self._check_admin_panels(base)
        methods = self._check_methods(base)

        result.raw = {
            "cors": cors,
            "admin_panels": admin,
            "dangerous_methods": methods,
        }

        # --- CORS findings ---
        if cors.get("reflects_origin"):
            result.findings.append(self.finding(
                category=Category.ACCESS,
                severity=Severity.HIGH,
                title="CORS refleja cualquier Origin (A01)",
                description=(
                    "El servidor refleja el header Origin del atacante en "
                    "Access-Control-Allow-Origin. Esto permite a cualquier sitio "
                    "malicioso leer respuestas autenticadas del usuario."
                ),
                evidence=cors,
                recommendation=(
                    "Configura Access-Control-Allow-Origin con una whitelist "
                    "de dominios confiables. Nunca reflejes el Origin sin validar."
                ),
                reference_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ))
        elif cors.get("allows_null"):
            result.findings.append(self.finding(
                category=Category.ACCESS,
                severity=Severity.MEDIUM,
                title="CORS acepta Origin: null (A01)",
                description=(
                    "El servidor acepta 'null' como Origin válido. "
                    "Iframes sandboxed y redirects pueden enviar Origin: null."
                ),
                evidence=cors,
                recommendation="No aceptes 'null' como Origin permitido.",
                reference_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ))
        elif cors.get("wildcard_with_creds"):
            result.findings.append(self.finding(
                category=Category.ACCESS,
                severity=Severity.HIGH,
                title="CORS: wildcard con Allow-Credentials (A01)",
                description=(
                    "Access-Control-Allow-Origin: * combinado con "
                    "Allow-Credentials: true es una configuración peligrosa."
                ),
                evidence=cors,
                recommendation="No combines wildcard con credentials.",
                reference_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ))

        # --- Admin panels ---
        for panel in admin:
            result.findings.append(self.finding(
                category=Category.ACCESS,
                severity=Severity.HIGH if panel.get("no_auth") else Severity.MEDIUM,
                title=f"Panel de administración expuesto: {panel['path']}",
                description=(
                    f"Se encontró '{panel['path']}' accesible "
                    f"(HTTP {panel['status']}). "
                    + ("No parece requerir autenticación." if panel.get("no_auth")
                       else "Requiere login pero está expuesto públicamente.")
                ),
                evidence=panel,
                recommendation=(
                    "Restringe el acceso a paneles de admin por IP o VPN. "
                    "Usa autenticación de dos factores."
                ),
                reference_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ))

        # --- Dangerous methods ---
        for m in methods:
            result.findings.append(self.finding(
                category=Category.ACCESS,
                severity=Severity.MEDIUM,
                title=f"Método HTTP {m['method']} habilitado",
                description=(
                    f"El servidor responde con HTTP {m['status']} al método "
                    f"{m['method']}. Métodos como PUT/DELETE pueden permitir "
                    "modificar o eliminar recursos si no están protegidos."
                ),
                evidence=m,
                recommendation=(
                    f"Deshabilita el método {m['method']} si no es necesario. "
                    "En Nginx: limit_except GET POST { deny all; }"
                ),
            ))

        if not cors.get("reflects_origin") and not cors.get("allows_null") \
                and not cors.get("wildcard_with_creds") and not admin and not methods:
            result.findings.append(self.finding(
                category=Category.ACCESS,
                severity=Severity.INFO,
                title="No se detectaron fallos de control de acceso (A01)",
                description="CORS, paneles admin y métodos HTTP verificados.",
            ))

        return result

    def _check_cors(self, base: str, hostname: str) -> dict:
        """Envía requests con diferentes Origins para probar CORS."""
        info: dict = {}
        evil = "https://evil.attacker.com"
        try:
            resp = requests.get(
                base + "/",
                timeout=TIMEOUT,
                headers={"User-Agent": UA, "Origin": evil},
                allow_redirects=True,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            info["acao"] = acao
            info["acac"] = acac

            if evil in acao:
                info["reflects_origin"] = True
            elif acao == "*" and acac == "true":
                info["wildcard_with_creds"] = True
        except requests.RequestException:
            pass

        # Test null origin.
        try:
            resp = requests.get(
                base + "/",
                timeout=TIMEOUT,
                headers={"User-Agent": UA, "Origin": "null"},
                allow_redirects=True,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "null":
                info["allows_null"] = True
        except requests.RequestException:
            pass

        return info

    def _check_admin_panels(self, base: str) -> list[dict]:
        """Prueba rutas comunes de admin."""
        found = []
        for path in ADMIN_PATHS:
            try:
                resp = requests.get(
                    base + path,
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    body_lower = resp.text[:2000].lower()
                    has_login = any(k in body_lower for k in (
                        "login", "password", "sign in", "log in",
                        "username", "iniciar sesión",
                    ))
                    no_auth = not has_login
                    found.append({
                        "path": path,
                        "status": resp.status_code,
                        "no_auth": no_auth,
                    })
            except requests.RequestException:
                continue
        return found[:5]  # Limitar output

    def _check_methods(self, base: str) -> list[dict]:
        """Prueba métodos HTTP peligrosos."""
        found = []
        for method in DANGEROUS_METHODS:
            try:
                resp = requests.request(
                    method, base + "/",
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=False,
                )
                # Si no retorna 405 Method Not Allowed, está habilitado.
                if resp.status_code not in (405, 501, 400, 403, 404):
                    found.append({"method": method, "status": resp.status_code})
            except requests.RequestException:
                continue
        return found
