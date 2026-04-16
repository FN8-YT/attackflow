"""
JS Client-Side Analysis — Endpoint & API Discovery.

Detecta endpoints, rutas y configuración expuesta en JavaScript:
- Rutas API explícitas (/api/v1/..., /rest/..., /graphql).
- Llamadas fetch(), XMLHttpRequest, axios, $.ajax.
- URLs absolutas a servicios internos o externos.
- WebSocket endpoints (ws://, wss://).
- Rutas admin/internas (/admin, /internal, /debug, /manage).
- Parámetros de query interesantes.
- File upload endpoints.
- Patrones de routing de frameworks SPA.

Esto es de alto valor para:
- Bug bounty hunters: descubre superficie de ataque oculta.
- Pentesters: mapea endpoints no documentados.
- Red team: identifica APIs internas accesibles.

Cómo funciona:
1. JSCollector recolecta todo el JS (inline + externo).
2. Se aplican regex por categoría de endpoint.
3. Se normaliza y deduplica.
4. Se clasifica cada endpoint por tipo y riesgo.

Limitaciones honestas:
- Solo detecta endpoints en strings literales (no dinámicos).
- Template literals con variables (${var}/path) se detectan parcialmente.
- Endpoints construidos por concatenación son difíciles de reconstruir.
- No verifica si los endpoints están activos/accesibles.
- Un scan más profundo requeriría fuzzing activo de los endpoints
  encontrados (fuera del alcance de este módulo).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult
from ._js_collector import JSCollector, JSSource


# ── API route patterns ───────────────────────────────────────
API_ROUTE_PATTERN = re.compile(
    r'["\'/]'
    r'((?:api|rest|v[1-9]|graphql|gql|webhook|ws)'
    r'(?:/[a-zA-Z0-9_\-{}:.]+){0,8})'
    r'[\s"\'/?,#]',
    re.IGNORECASE,
)

# ── Fetch/XHR/axios call patterns ────────────────────────────
FETCH_PATTERN = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch|request)|'
    r'\.ajax|\.open)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# ── Absolute URL in JS ──────────────────────────────────────
ABSOLUTE_URL_PATTERN = re.compile(
    r'["\']'
    r'(https?://[a-zA-Z0-9._\-]+(?::\d+)?(?:/[^\s"\'<>{}|\\^`]{0,200})?)'
    r'["\']',
)

# ── WebSocket pattern ────────────────────────────────────────
WEBSOCKET_PATTERN = re.compile(
    r'["\']'
    r'(wss?://[a-zA-Z0-9._\-]+(?::\d+)?(?:/[^\s"\'<>]+)?)'
    r'["\']',
)

# ── Relative paths that look like routes ─────────────────────
ROUTE_PATTERN = re.compile(
    r'["\'](/'
    r'(?:admin|manage|dashboard|internal|debug|config|settings|'
    r'user|users|account|profile|auth|login|logout|register|signup|'
    r'upload|file|download|export|import|report|backup|'
    r'panel|console|monitor|health|status|metrics|'
    r'search|webhook|callback|notify|event|queue|worker|cron|task)'
    r'(?:/[a-zA-Z0-9_\-{}:.]+){0,6})'
    r'["\']',
    re.IGNORECASE,
)

# ── Query parameter patterns ────────────────────────────────
PARAM_PATTERN = re.compile(
    r'[?&]((?:token|key|secret|password|auth|session|'
    r'api_key|access_token|redirect|callback|next|return|url|'
    r'file|path|dir|cmd|exec|query|search|id|user_id|email)'
    r')=',
    re.IGNORECASE,
)

# ── SPA router patterns ─────────────────────────────────────
SPA_ROUTE_PATTERN = re.compile(
    r'(?:path|route|to|href|navigate|push|replace)\s*[=:]\s*'
    r'["\'](/[a-zA-Z0-9_\-/{}:.]+)["\']',
    re.IGNORECASE,
)

# ── Static assets to ignore ─────────────────────────────────
IGNORED_EXTENSIONS = {
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map', '.mp4', '.webp',
    '.pdf', '.zip', '.tar', '.gz',
}

# ── High-interest admin/debug paths ─────────────────────────
ADMIN_KEYWORDS = {
    'admin', 'manage', 'internal', 'debug', 'console',
    'panel', 'dashboard', 'monitor', 'config', 'settings',
    'backup', 'export', 'cron', 'worker', 'queue',
}


class JSEndpointsScanner(BaseScanner):
    name = "js_endpoints"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base_url += f":{target.port}"

        collector = JSCollector(context.body_text, base_url)
        sources = collector.collect_all(fetch_external=True)
        combined = collector.combined_content(sources)

        api_routes = self._find_api_routes(combined)
        fetch_calls = self._find_fetch_calls(combined)
        absolute_urls = self._find_absolute_urls(combined, target.hostname)
        websockets = self._find_websockets(combined)
        admin_routes = self._find_admin_routes(combined)
        params = self._find_interesting_params(combined)
        spa_routes = self._find_spa_routes(combined)

        # Merge all unique endpoints.
        all_endpoints = set()
        all_endpoints.update(api_routes)
        all_endpoints.update(fetch_calls)
        all_endpoints.update(admin_routes)
        all_endpoints.update(spa_routes)

        result.raw = {
            "collection": collector.stats_dict(),
            "api_routes": len(api_routes),
            "fetch_calls": len(fetch_calls),
            "absolute_urls": len(absolute_urls),
            "websockets": len(websockets),
            "admin_routes": len(admin_routes),
            "interesting_params": len(params),
            "spa_routes": len(spa_routes),
            "unique_endpoints": len(all_endpoints),
        }

        # --- API routes ---
        if api_routes:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(api_routes)} ruta(s) API descubierta(s) en JS",
                description=(
                    "Se descubrieron rutas API en el código JavaScript. "
                    "Estas rutas exponen la superficie de ataque de la "
                    "aplicación y pueden incluir endpoints no documentados."
                ),
                evidence={
                    "routes": sorted(api_routes)[:25],
                    "count": len(api_routes),
                },
                recommendation=(
                    "Asegura que todos los endpoints tengan autenticación "
                    "y autorización adecuadas. Documenta y audita cada "
                    "endpoint descubierto."
                ),
            ))

        # --- Fetch/XHR calls ---
        if fetch_calls:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.LOW,
                title=f"{len(fetch_calls)} llamada(s) HTTP descubierta(s) en JS",
                description=(
                    "Se detectaron llamadas fetch/XHR/axios a endpoints "
                    "específicos. Mapean las comunicaciones cliente→servidor."
                ),
                evidence={
                    "calls": sorted(fetch_calls)[:25],
                    "count": len(fetch_calls),
                },
                recommendation=(
                    "Verifica que cada endpoint valide autenticación, "
                    "autorización y parámetros de entrada."
                ),
            ))

        # --- External URLs ---
        if absolute_urls:
            # Separate first-party from third-party.
            third_party = [
                u for u in absolute_urls
                if target.hostname not in u
            ]
            first_party = [
                u for u in absolute_urls
                if target.hostname in u
            ]

            if third_party:
                result.findings.append(self.finding(
                    category=Category.JS,
                    severity=Severity.LOW,
                    title=f"{len(third_party)} URL(s) de terceros en JS",
                    description=(
                        "El JavaScript referencia servicios externos. "
                        "Esto mapea dependencias y servicios third-party."
                    ),
                    evidence={
                        "urls": sorted(third_party)[:20],
                        "count": len(third_party),
                    },
                    recommendation=(
                        "Audita las dependencias third-party. Asegura "
                        "que las comunicaciones sean por HTTPS."
                    ),
                ))

            if first_party:
                result.findings.append(self.finding(
                    category=Category.JS,
                    severity=Severity.INFO,
                    title=f"{len(first_party)} URL(s) first-party en JS",
                    description="URLs del propio dominio encontradas en JavaScript.",
                    evidence={
                        "urls": sorted(first_party)[:20],
                        "count": len(first_party),
                    },
                ))

        # --- WebSockets ---
        if websockets:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(websockets)} endpoint(s) WebSocket en JS",
                description=(
                    "Se detectaron conexiones WebSocket. Los WebSockets "
                    "mantienen conexiones persistentes y pueden ser "
                    "vectores de ataque si no validan autenticación "
                    "y origin correctamente."
                ),
                evidence={"endpoints": sorted(websockets)[:10]},
                recommendation=(
                    "Verifica que los WebSockets validen el Origin header, "
                    "requieran autenticación y saniticen mensajes."
                ),
            ))

        # --- Admin/internal routes ---
        if admin_routes:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.HIGH,
                title=f"{len(admin_routes)} ruta(s) admin/interna(s) en JS",
                description=(
                    "Se descubrieron rutas que parecen ser de "
                    "administración, debug o uso interno. Estas rutas "
                    "son de alto interés para un atacante."
                ),
                evidence={
                    "routes": sorted(admin_routes)[:15],
                    "count": len(admin_routes),
                },
                recommendation=(
                    "Restringe el acceso a rutas admin por roles/permisos. "
                    "No expongas rutas internas en JavaScript de producción. "
                    "Usa code splitting para cargar rutas admin solo "
                    "cuando el usuario es admin."
                ),
            ))

        # --- Interesting parameters ---
        if params:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(params)} parámetro(s) interesante(s) en JS",
                description=(
                    "Se detectaron parámetros de query con nombres "
                    "sensibles (token, key, redirect, etc.). "
                    "Son vectores potenciales para IDOR, open redirect "
                    "y parameter tampering."
                ),
                evidence={"params": sorted(params)[:15]},
                recommendation=(
                    "Valida y sanitiza todos los parámetros server-side. "
                    "No confíes en valores de query string para "
                    "autenticación o autorización."
                ),
            ))

        total = (
            len(api_routes) + len(fetch_calls) + len(absolute_urls)
            + len(websockets) + len(admin_routes) + len(params)
        )
        if total == 0:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.INFO,
                title="No se descubrieron endpoints en JS",
                description=(
                    f"Se analizaron {collector.stats.inline_count} scripts "
                    f"inline y {collector.stats.external_fetched} externos. "
                    "No se encontraron rutas API, endpoints ni parámetros "
                    "interesantes."
                ),
            ))

        return result

    # ── Discovery methods ────────────────────────────────────

    def _find_api_routes(self, js: str) -> list[str]:
        routes = set()
        for m in API_ROUTE_PATTERN.finditer(js):
            route = "/" + m.group(1).strip("/")
            if not self._is_ignored(route):
                routes.add(route)
        return sorted(routes)[:50]

    def _find_fetch_calls(self, js: str) -> list[str]:
        calls = set()
        for m in FETCH_PATTERN.finditer(js):
            url = m.group(1).strip()
            if url and not self._is_ignored(url) and len(url) > 1:
                calls.add(url[:200])
        return sorted(calls)[:50]

    def _find_absolute_urls(self, js: str, own_hostname: str) -> list[str]:
        urls = set()
        for m in ABSOLUTE_URL_PATTERN.finditer(js):
            url = m.group(1)
            if self._is_ignored(url):
                continue
            # Skip common CDN/analytics that add noise.
            parsed = urlparse(url)
            if parsed.hostname and any(
                cdn in parsed.hostname for cdn in (
                    'googleapis.com', 'gstatic.com', 'cdnjs.cloudflare.com',
                    'cdn.jsdelivr.net', 'unpkg.com', 'fonts.googleapis.com',
                    'google-analytics.com', 'googletagmanager.com',
                    'facebook.net', 'twitter.com',
                )
            ):
                continue
            urls.add(url[:200])
        return sorted(urls)[:50]

    def _find_websockets(self, js: str) -> list[str]:
        ws = set()
        for m in WEBSOCKET_PATTERN.finditer(js):
            ws.add(m.group(1)[:200])
        return sorted(ws)[:10]

    def _find_admin_routes(self, js: str) -> list[str]:
        routes = set()
        for m in ROUTE_PATTERN.finditer(js):
            route = m.group(1)
            # Only include if it has an admin-like keyword.
            path_lower = route.lower()
            if any(kw in path_lower for kw in ADMIN_KEYWORDS):
                routes.add(route)
        return sorted(routes)[:20]

    def _find_interesting_params(self, js: str) -> list[str]:
        params = set()
        for m in PARAM_PATTERN.finditer(js):
            params.add(m.group(1).lower())
        return sorted(params)[:20]

    def _find_spa_routes(self, js: str) -> list[str]:
        routes = set()
        for m in SPA_ROUTE_PATTERN.finditer(js):
            route = m.group(1)
            if not self._is_ignored(route) and len(route) > 1:
                routes.add(route)
        return sorted(routes)[:30]

    @staticmethod
    def _is_ignored(url: str) -> bool:
        """Filtra recursos estáticos que no son endpoints."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)
