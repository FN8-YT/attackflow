"""
Sensitive path discovery — probe for exposed admin panels, config files,
backup files, debug endpoints and other attack surface.

Diseñado para pentesters: descubre recursos que NO deberían ser accesibles
públicamente. Usa concurrencia para ser rápido (ThreadPoolExecutor).

Seguridad:
- Timeout corto (3s por default) para no bloquear el worker.
- User-Agent identificado como AttackFlow-Monitor.
- allow_redirects=False: nos interesa el status raw del path, no el destino.
- Solo reporta paths con código HTTP considerado "presente"
  (200/201/204/301/302/307/308/401/403) — los 404/410 son ignorados.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# (path, label, severity, http_method)
# Ordenados de más crítico a menos para facilitar la lectura del output.
SENSITIVE_PATHS: list[tuple[str, str, str, str]] = [
    # ── CRITICAL: exposición directa de datos/código ──────────────────────
    ("/.git/HEAD",              "Git Repository",          "critical", "GET"),
    ("/.git/config",            "Git Config",              "critical", "GET"),
    ("/.git/COMMIT_EDITMSG",    "Git Commit History",      "critical", "GET"),
    ("/.env",                   ".env File",               "critical", "GET"),
    ("/.env.local",             ".env.local",              "critical", "GET"),
    ("/.env.production",        ".env.production",         "critical", "GET"),
    ("/backup.sql",             "Database Backup (SQL)",   "critical", "HEAD"),
    ("/dump.sql",               "Database Dump",           "critical", "HEAD"),
    ("/db.sql",                 "Database Dump",           "critical", "HEAD"),
    ("/database.sql",           "Database Backup",         "critical", "HEAD"),
    ("/backup.zip",             "Backup Archive (ZIP)",    "critical", "HEAD"),
    ("/backup.tar.gz",          "Backup Archive (tar.gz)", "critical", "HEAD"),
    ("/config.php",             "PHP Config File",         "critical", "GET"),
    ("/config.yml",             "Config YAML",             "critical", "GET"),
    ("/config.yaml",            "Config YAML",             "critical", "GET"),
    ("/config.json",            "Config JSON",             "critical", "GET"),
    ("/wp-config.php",          "WordPress Config",        "critical", "GET"),
    ("/settings.py",            "Django Settings",         "critical", "GET"),
    # ── HIGH: paneles admin / management ──────────────────────────────────
    ("/admin/",                 "Admin Panel",             "high",     "GET"),
    ("/admin",                  "Admin Panel",             "high",     "GET"),
    ("/administrator/",         "Admin Panel",             "high",     "GET"),
    ("/wp-admin/",              "WordPress Admin",         "high",     "GET"),
    ("/wp-login.php",           "WordPress Login",         "high",     "GET"),
    ("/phpmyadmin/",            "phpMyAdmin",              "high",     "GET"),
    ("/pma/",                   "phpMyAdmin (pma)",        "high",     "GET"),
    ("/phpinfo.php",            "PHP Info Page",           "high",     "GET"),
    ("/server-status",          "Apache Server Status",    "high",     "GET"),
    ("/server-info",            "Apache Server Info",      "high",     "GET"),
    ("/actuator/env",           "Spring /actuator/env",    "high",     "GET"),
    ("/actuator/heapdump",      "Spring Heap Dump",        "high",     "HEAD"),
    ("/actuator/beans",         "Spring Bean Config",      "high",     "GET"),
    ("/actuator/mappings",      "Spring URL Mappings",     "high",     "GET"),
    ("/manage/",                "Django Manage (typo?)",   "high",     "GET"),
    ("/console",                "Dev Console",             "high",     "GET"),
    ("/h2-console",             "H2 Database Console",     "high",     "GET"),
    # ── MEDIUM: APIs / debug / docs ───────────────────────────────────────
    ("/actuator/",              "Spring Actuator",         "medium",   "GET"),
    ("/actuator/health",        "Spring /health",          "medium",   "GET"),
    ("/swagger-ui.html",        "Swagger UI",              "medium",   "GET"),
    ("/swagger-ui/",            "Swagger UI",              "medium",   "GET"),
    ("/swagger/",               "Swagger",                 "medium",   "GET"),
    ("/api-docs",               "API Docs",                "medium",   "GET"),
    ("/api-docs/",              "API Docs",                "medium",   "GET"),
    ("/v2/api-docs",            "Swagger v2 API Docs",     "medium",   "GET"),
    ("/graphql",                "GraphQL Endpoint",        "medium",   "POST"),
    ("/graphiql",               "GraphiQL IDE",            "medium",   "GET"),
    ("/crossdomain.xml",        "CrossDomain Policy",      "medium",   "GET"),
    ("/.htaccess",              "Htaccess File",           "medium",   "GET"),
    ("/web.config",             "Web.config",              "medium",   "GET"),
    ("/elmah.axd",              "ELMAH Error Logs",        "medium",   "GET"),
    ("/trace.axd",              "ASP.NET Trace",           "medium",   "GET"),
    # ── INFO: recon ───────────────────────────────────────────────────────
    ("/robots.txt",             "Robots.txt",              "info",     "GET"),
    ("/sitemap.xml",            "Sitemap",                 "info",     "GET"),
    ("/.well-known/security.txt", "Security.txt",          "info",     "GET"),
    ("/humans.txt",             "Humans.txt",              "info",     "GET"),
    ("/favicon.ico",            "Favicon",                 "info",     "HEAD"),
]

# HTTP status codes que consideramos "existe" (no 404/410/gone)
FOUND_STATUSES: frozenset[int] = frozenset({
    200, 201, 204,
    301, 302, 307, 308,
    401, 403,          # auth required / forbidden = existe pero está protegido
    500,               # error del servidor = existe algo ahí
})

UA = "AttackFlow-Monitor/1.0"


def check_sensitive_paths(target_url: str, timeout: int = 3) -> list[dict]:
    """
    Prueba cada path conocido contra el origen del target.

    Returns:
        Lista de paths encontrados (status in FOUND_STATUSES), ordenada
        por severidad (critical → info) y luego por path.
        Cada entry: {path, label, severity, status_code}
    """
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    found: list[dict] = []

    def _probe(path: str, label: str, severity: str, method: str) -> dict | None:
        url = base + path
        try:
            resp = requests.request(
                method if method != "POST" else "GET",  # GraphQL → GET primero
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": UA},
                verify=True,
            )
            if resp.status_code in FOUND_STATUSES:
                return {
                    "path":        path,
                    "label":       label,
                    "severity":    severity,
                    "status_code": resp.status_code,
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(_probe, path, label, sev, method): path
            for path, label, sev, method in SENSITIVE_PATHS
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                found.append(result)

    _order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    found.sort(key=lambda x: (_order.get(x["severity"], 4), x["path"]))
    return found
