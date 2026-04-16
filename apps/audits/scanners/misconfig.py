"""
Scanner de misconfigurations comunes.

Detecta:
- Directory listing habilitado
- Archivos sensibles expuestos (.git/HEAD, .env, .DS_Store, etc.)
- Endpoints de debug activos (phpinfo, Django debug, Symfony profiler)
- Open redirect en parámetros comunes

MODO ACTIVO: hace requests adicionales a rutas conocidas.
"""
from __future__ import annotations

import logging
import re

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

MISCONFIG_TIMEOUT = 8

# Archivos sensibles con sus indicadores de "encontrado".
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, indicator_in_body, description)
    ("/.git/HEAD", "ref: refs/", "Repositorio Git expuesto"),
    ("/.env", "DB_PASSWORD", "Archivo .env con credenciales expuesto"),
    ("/.env", "SECRET_KEY", "Archivo .env con credenciales expuesto"),
    ("/.DS_Store", "\x00\x00\x00\x01Bud1", "Archivo .DS_Store de macOS expuesto"),
    ("/wp-config.php.bak", "DB_NAME", "Backup de configuración WordPress expuesto"),
    ("/server-status", "Apache Server Status", "Apache server-status expuesto"),
    ("/server-info", "Apache Server Information", "Apache server-info expuesto"),
    ("/.htaccess", "RewriteEngine", "Archivo .htaccess accesible"),
    ("/robots.txt", "Disallow", "robots.txt encontrado (informativo)"),
    ("/sitemap.xml", "<?xml", "sitemap.xml encontrado (informativo)"),
    ("/crossdomain.xml", "cross-domain-policy", "crossdomain.xml encontrado"),
    ("/.well-known/security.txt", "Contact:", "security.txt encontrado"),
    ("/phpinfo.php", "phpinfo()", "phpinfo() expuesto"),
    ("/info.php", "phpinfo()", "phpinfo() expuesto"),
    ("/elmah.axd", "Error Log", "ELMAH error log expuesto (ASP.NET)"),
    ("/trace.axd", "Trace", "ASP.NET Trace expuesto"),
    ("/__debug__/", "djdt", "Django Debug Toolbar expuesto"),
    ("/_profiler/", "Symfony Profiler", "Symfony Profiler expuesto"),
    ("/actuator/health", '"status"', "Spring Boot Actuator expuesto"),
    ("/actuator/env", '"propertySources"', "Spring Boot Actuator /env expuesto"),
]

# Parámetros comunes de redirect.
REDIRECT_PARAMS = ("redirect", "url", "next", "return", "returnTo", "goto", "continue")


class MisconfigScanner(BaseScanner):
    name = "misconfig"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        base = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base += f":{target.port}"

        exposed_files: list[dict] = []
        info_files: list[dict] = []
        dir_listing = False

        # --- Archivos sensibles ---
        checked_paths: set[str] = set()
        for path, indicator, desc in SENSITIVE_PATHS:
            if path in checked_paths:
                continue
            checked_paths.add(path)

            try:
                resp = requests.get(
                    f"{base}{path}",
                    timeout=MISCONFIG_TIMEOUT,
                    allow_redirects=False,
                    headers={"User-Agent": "SecurityAuditBot/0.1"},
                )
                if resp.status_code == 200 and indicator in resp.text:
                    is_info = path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
                    entry = {"path": path, "description": desc, "status": resp.status_code}
                    if is_info:
                        info_files.append(entry)
                    else:
                        exposed_files.append(entry)
            except requests.RequestException:
                continue

        # --- Directory listing ---
        for test_path in ("/", "/images/", "/assets/", "/uploads/", "/static/"):
            try:
                resp = requests.get(
                    f"{base}{test_path}",
                    timeout=MISCONFIG_TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "SecurityAuditBot/0.1"},
                )
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if ("index of /" in body_lower or
                            "directory listing" in body_lower or
                            '<pre><a href="' in body_lower):
                        dir_listing = True
                        break
            except requests.RequestException:
                continue

        # --- Open redirect ---
        open_redirects: list[dict] = []
        test_domain = "https://evil.example.com"
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        parsed = urlparse(target.url)
        existing_params = parse_qs(parsed.query, keep_blank_values=True)

        params_to_test = [p for p in existing_params if p.lower() in REDIRECT_PARAMS]
        if not params_to_test:
            params_to_test = [p for p in REDIRECT_PARAMS[:3]]

        for param in params_to_test[:3]:
            test_params = dict(existing_params)
            test_params[param] = [test_domain]
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), "",
            ))
            try:
                resp = requests.get(
                    test_url,
                    timeout=MISCONFIG_TIMEOUT,
                    allow_redirects=False,
                    headers={"User-Agent": "SecurityAuditBot/0.1"},
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.example.com" in location:
                        open_redirects.append({
                            "param": param,
                            "redirect_to": location,
                        })
            except requests.RequestException:
                continue

        # --- Resultados ---
        result.raw = {
            "exposed_files": len(exposed_files),
            "info_files": len(info_files),
            "dir_listing": dir_listing,
            "open_redirects": len(open_redirects),
        }

        # Findings: archivos sensibles
        for f in exposed_files:
            severity = Severity.CRITICAL if ".env" in f["path"] or ".git" in f["path"] else Severity.HIGH
            result.findings.append(
                self.finding(
                    category=Category.MISCONFIG,
                    severity=severity,
                    title=f["description"],
                    description=(
                        f"Se encontró '{f['path']}' accesible públicamente. "
                        "Esto puede exponer credenciales, código fuente u otra "
                        "información sensible."
                    ),
                    evidence=f,
                    recommendation=(
                        "Bloquea el acceso a este recurso en la configuración "
                        "del servidor web o elimínalo del servidor."
                    ),
                )
            )

        # Findings: informativos
        for f in info_files:
            result.findings.append(
                self.finding(
                    category=Category.MISCONFIG,
                    severity=Severity.INFO,
                    title=f["description"],
                    description=f"Se encontró '{f['path']}' accesible.",
                    evidence=f,
                )
            )

        # Directory listing
        if dir_listing:
            result.findings.append(
                self.finding(
                    category=Category.MISCONFIG,
                    severity=Severity.MEDIUM,
                    title="Directory listing habilitado",
                    description=(
                        "El servidor muestra listados de directorios, lo que "
                        "permite a atacantes enumerar archivos y directorios."
                    ),
                    recommendation=(
                        "Desactiva directory listing: Options -Indexes (Apache) "
                        "o autoindex off (Nginx)."
                    ),
                )
            )

        # Open redirects
        for redir in open_redirects:
            result.findings.append(
                self.finding(
                    category=Category.MISCONFIG,
                    severity=Severity.MEDIUM,
                    title=f"Open redirect en parámetro '{redir['param']}'",
                    description=(
                        f"El parámetro '{redir['param']}' permite redirigir a "
                        "dominios externos sin validación. Esto se usa en ataques "
                        "de phishing."
                    ),
                    evidence=redir,
                    recommendation=(
                        "Valida que la URL de redirect pertenezca al mismo dominio "
                        "o usa una whitelist de destinos permitidos."
                    ),
                    reference_url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                )
            )

        if not exposed_files and not dir_listing and not open_redirects:
            result.findings.append(
                self.finding(
                    category=Category.MISCONFIG,
                    severity=Severity.INFO,
                    title="No se detectaron misconfigurations comunes",
                    description=(
                        "No se encontraron archivos sensibles expuestos, "
                        "directory listing ni open redirects."
                    ),
                )
            )

        return result
