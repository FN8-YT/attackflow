"""
OWASP A10 — Server-Side Request Forgery (SSRF).

Detecta indicadores de SSRF desde fuera:
- Parámetros URL que aceptan URLs/dominios (url=, redirect=, next=, etc.).
- Open redirects (el servidor redirige a dominios externos).
- Redirect chains que podrían ser abusadas.
- Parámetros de inclusión de archivos/recursos remotos.

MODO ACTIVO: envía requests con payloads de redirección.

Limitaciones honestas:
- SSRF real requiere que el servidor haga requests internos.
  Desde fuera solo detectamos vectores potenciales.
- No puede confirmar si el backend realmente hace fetch de URLs.
- Open redirect es el indicador externo más confiable.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlencode

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

TIMEOUT = 8
UA = "SecurityAuditBot/0.1"

# Parámetros que comúnmente aceptan URLs.
URL_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "return_to", "returnTo",
    "continue", "dest", "destination", "go",
    "target", "link", "site", "ref",
    "callback", "cb", "return_url",
]

# Payload de redirección para probar open redirect.
REDIRECT_TARGET = "https://evil.attacker.test"


class SsrfScanner(BaseScanner):
    name = "ssrf_scan"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        base = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base += f":{target.port}"

        # Analyze HTML for URL-accepting parameters.
        url_params = self._find_url_params(context.body_text, base)

        # Test for open redirects.
        open_redirects = self._test_open_redirects(base)

        # Check for redirect chains on the main page.
        redirect_chain = self._analyze_redirect_chain(context)

        result.raw = {
            "url_params_found": len(url_params),
            "open_redirects": len(open_redirects),
            "redirect_chain": redirect_chain,
        }

        # --- Open redirects ---
        for redir in open_redirects:
            result.findings.append(self.finding(
                category=Category.SSRF,
                severity=Severity.HIGH,
                title=f"Open redirect detectado: {redir['param']} (A10)",
                description=(
                    f"El parámetro '{redir['param']}' permite redirigir "
                    f"a dominios externos. URL probada: {redir['test_url']}. "
                    "Los atacantes usan open redirects para phishing y como "
                    "trampolín para SSRF interno."
                ),
                evidence=redir,
                recommendation=(
                    "Valida y whitelist las URLs de redirección. "
                    "Solo permite rutas relativas o dominios propios. "
                    "Nunca redirijas a URLs proporcionadas por el usuario "
                    "sin validación."
                ),
                reference_url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            ))

        # --- URL parameters detected ---
        if url_params and not open_redirects:
            result.findings.append(self.finding(
                category=Category.SSRF,
                severity=Severity.MEDIUM,
                title=f"{len(url_params)} parámetro(s) URL potencialmente riesgoso(s) (A10)",
                description=(
                    "Se detectaron parámetros en enlaces que aceptan URLs. "
                    "Si el servidor procesa estas URLs internamente (fetch, "
                    "redirect, include), podría ser vulnerable a SSRF."
                ),
                evidence={"params": url_params[:10]},
                recommendation=(
                    "Revisa si estos parámetros son procesados server-side. "
                    "Implementa whitelist de dominios/IPs permitidos y "
                    "bloquea rangos internos (127.0.0.1, 10.x, 169.254.x, etc.)."
                ),
                reference_url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            ))

        # --- Suspicious redirect chain ---
        if redirect_chain.get("excessive"):
            result.findings.append(self.finding(
                category=Category.SSRF,
                severity=Severity.LOW,
                title="Cadena de redirecciones excesiva (A10)",
                description=(
                    f"La página principal tiene {redirect_chain['count']} "
                    "redirecciones. Cadenas largas pueden indicar "
                    "configuraciones de proxy/redirect explotables."
                ),
                evidence=redirect_chain,
                recommendation="Reduce las redirecciones al mínimo necesario.",
            ))

        if not open_redirects and not url_params \
                and not redirect_chain.get("excessive"):
            result.findings.append(self.finding(
                category=Category.SSRF,
                severity=Severity.INFO,
                title="No se detectaron vectores de SSRF (A10)",
                description=(
                    "No se encontraron open redirects ni parámetros URL "
                    "sospechosos en la respuesta analizada."
                ),
            ))

        return result

    def _find_url_params(self, html: str, base: str) -> list[dict]:
        """Busca parámetros en links/forms que aceptan URLs."""
        found = []

        # Extract all href/action URLs with parameters.
        links = re.findall(
            r'(?:href|action|src)\s*=\s*["\']([^"\']*\?[^"\']+)["\']',
            html, re.IGNORECASE,
        )

        for link in links:
            for param in URL_PARAMS:
                pattern = rf'[?&]{re.escape(param)}='
                if re.search(pattern, link, re.IGNORECASE):
                    found.append({
                        "url": link[:200],
                        "param": param,
                    })

        # Deduplicate by param name.
        seen = set()
        unique = []
        for f in found:
            if f["param"] not in seen:
                seen.add(f["param"])
                unique.append(f)

        return unique

    def _test_open_redirects(self, base: str) -> list[dict]:
        """Prueba parámetros de redirect comunes con URL externa."""
        redirects_found = []

        for param in URL_PARAMS[:10]:  # Test top 10 most common.
            test_url = f"{base}/?{urlencode({param: REDIRECT_TARGET})}"
            try:
                resp = requests.get(
                    test_url,
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=False,
                )
                # Check if server redirects to our evil domain.
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.attacker.test" in location:
                        redirects_found.append({
                            "param": param,
                            "test_url": test_url,
                            "redirect_to": location[:200],
                            "status": resp.status_code,
                        })
            except requests.RequestException:
                continue

        return redirects_found

    def _analyze_redirect_chain(self, context: ScanContext) -> dict:
        """Analiza la cadena de redirecciones de la respuesta principal."""
        if not context.has_http:
            return {}

        resp = context.http_response
        history = resp.history if resp.history else []

        chain = [
            {"url": r.url[:200], "status": r.status_code}
            for r in history
        ]

        return {
            "count": len(chain),
            "chain": chain[:5],
            "excessive": len(chain) > 3,
        }
