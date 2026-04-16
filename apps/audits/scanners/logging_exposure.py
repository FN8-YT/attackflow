"""
OWASP A09 — Security Logging and Monitoring Failures.

Detecta indicadores externamente visibles:
- Endpoints de logs/debug accesibles públicamente.
- Stack traces o errores detallados en respuestas (complementa A04).
- Ausencia de headers de seguridad relacionados con reporting (Report-To, NEL).
- Archivos de log expuestos (.log, access.log, error.log, debug.log).

MODO ACTIVO: envía requests a rutas comunes de logs/debug.

Limitaciones honestas:
- No puede verificar si existe logging interno real.
- No puede evaluar la calidad del SIEM ni alertas.
- Solo detecta evidencia externa de logging deficiente o expuesto.
"""
from __future__ import annotations

import logging

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

TIMEOUT = 8
UA = "SecurityAuditBot/0.1"

# Rutas comunes donde se exponen logs/debug info.
LOG_PATHS = [
    "/debug.log", "/error.log", "/access.log",
    "/logs/", "/log/", "/server.log",
    "/wp-content/debug.log",
    "/var/log/", "/tmp/logs/",
    "/elmah.axd", "/trace.axd",           # ASP.NET error logs
    "/server-status", "/server-info",       # Apache status
    "/nginx_status",                        # Nginx status
    "/_debug/", "/debug/",
    "/actuator/", "/actuator/health",       # Spring Boot
    "/actuator/env", "/actuator/loggers",
    "/__debug__/",                          # Django debug toolbar
    "/phpinfo.php",                         # PHP info
    "/info.php",
    "/console/", "/admin/console/",         # Dev consoles
    "/.env",                                # Environment file
    "/config.php", "/configuration.php",
]


class LoggingExposureScanner(BaseScanner):
    name = "logging_exposure"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        base = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base += f":{target.port}"

        exposed = self._probe_log_endpoints(base)
        reporting = self._check_reporting_headers(context)

        result.raw = {
            "exposed_endpoints": len(exposed),
            "reporting_headers": reporting,
        }

        # --- Exposed log/debug endpoints ---
        for ep in exposed:
            severity = Severity.HIGH if ep.get("sensitive") else Severity.MEDIUM
            result.findings.append(self.finding(
                category=Category.LOGGING,
                severity=severity,
                title=f"Endpoint expuesto: {ep['path']} (A09)",
                description=(
                    f"El recurso '{ep['path']}' es accesible públicamente "
                    f"(HTTP {ep['status']}). "
                    f"Tipo detectado: {ep.get('type', 'desconocido')}. "
                    "Los atacantes usan estos endpoints para recopilar "
                    "información interna del servidor."
                ),
                evidence=ep,
                recommendation=(
                    f"Restringe el acceso a '{ep['path']}' por IP, VPN o "
                    "elimínalo de producción. Nunca expongas logs, debug "
                    "tools o configuración al público."
                ),
                reference_url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            ))

        # --- Reporting headers ---
        if not reporting.get("has_any"):
            result.findings.append(self.finding(
                category=Category.LOGGING,
                severity=Severity.LOW,
                title="Sin headers de security reporting (A09)",
                description=(
                    "No se detectaron headers Report-To, NEL (Network Error "
                    "Logging) ni Reporting-Endpoints. Estos headers permiten "
                    "recibir reportes automáticos de errores de seguridad "
                    "del navegador."
                ),
                evidence=reporting,
                recommendation=(
                    "Configura Report-To y NEL para recibir reportes de "
                    "errores de red y CSP violations. Esto mejora la "
                    "visibilidad sobre ataques en curso."
                ),
                reference_url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            ))

        if not exposed and reporting.get("has_any"):
            result.findings.append(self.finding(
                category=Category.LOGGING,
                severity=Severity.INFO,
                title="No se detectaron fallos de logging/monitoreo (A09)",
                description=(
                    "No hay endpoints de logs expuestos y se usan headers "
                    "de reporting."
                ),
            ))

        return result

    def _probe_log_endpoints(self, base: str) -> list[dict]:
        """Prueba rutas comunes de logs y debug."""
        exposed = []
        for path in LOG_PATHS:
            try:
                resp = requests.get(
                    base + path,
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=False,
                )
                if resp.status_code not in (200, 403):
                    continue

                body = resp.text[:3000].lower()
                info: dict = {
                    "path": path,
                    "status": resp.status_code,
                    "sensitive": False,
                    "type": "unknown",
                }

                # 403 = exists but blocked (still worth noting).
                if resp.status_code == 403:
                    info["type"] = "blocked (exists)"
                    info["sensitive"] = False
                    # Don't report blocked endpoints to reduce noise.
                    continue

                # Classify what we found.
                if any(k in body for k in ("stack trace", "traceback",
                                           "exception", "error log")):
                    info["type"] = "error log / stack trace"
                    info["sensitive"] = True
                elif any(k in body for k in ("phpinfo()", "php version",
                                             "configuration")):
                    info["type"] = "server info / phpinfo"
                    info["sensitive"] = True
                elif any(k in body for k in (".env", "db_password",
                                             "secret_key", "api_key")):
                    info["type"] = "configuration / secrets"
                    info["sensitive"] = True
                elif any(k in body for k in ("actuator", "beans", "loggers",
                                             "health")):
                    info["type"] = "Spring Boot Actuator"
                    info["sensitive"] = True
                elif any(k in path.lower() for k in (".log", "debug",
                                                     "trace", "elmah")):
                    info["type"] = "log / debug file"
                    info["sensitive"] = True
                elif "index of" in body or "directory listing" in body:
                    info["type"] = "directory listing"
                    info["sensitive"] = True
                else:
                    # Generic 200 response — might be a custom page.
                    # Only report if it looks like actual content, not a
                    # generic redirect-to-homepage.
                    content_len = len(resp.text)
                    if content_len < 100:
                        continue
                    info["type"] = "accessible endpoint"

                exposed.append(info)

            except requests.RequestException:
                continue

        return exposed[:10]  # Limitar output.

    def _check_reporting_headers(self, context: ScanContext) -> dict:
        """Verifica headers de security reporting."""
        if not context.has_http:
            return {"has_any": False}

        headers = context.http_response.headers
        report_to = headers.get("Report-To", "")
        nel = headers.get("NEL", "")
        reporting_endpoints = headers.get("Reporting-Endpoints", "")

        has_any = bool(report_to or nel or reporting_endpoints)
        return {
            "has_any": has_any,
            "report_to": bool(report_to),
            "nel": bool(nel),
            "reporting_endpoints": bool(reporting_endpoints),
        }
