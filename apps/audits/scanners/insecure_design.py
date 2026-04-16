"""
OWASP A04 — Insecure Design.

Detecta indicadores de diseño inseguro externamente:
- Verbose error messages / stack traces en respuestas de error.
- Modo debug activo (frameworks comunes).
- Ausencia de rate limiting (envía múltiples requests rápidos).
- Information disclosure en HTML comments.

MODO ACTIVO: envía requests adicionales para provocar errores.

Limitaciones honestas:
- Insecure Design es mayormente un problema de arquitectura interna.
  Desde fuera solo podemos detectar síntomas visibles.
"""
from __future__ import annotations

import logging
import re
import time

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

TIMEOUT = 8
UA = "SecurityAuditBot/0.1"

# Patrones que indican stack traces / debug info.
ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at .+\.java:\d+\)", "Java stack trace"),
    (r"at .+\.cs:\d+\)", "C# stack trace"),
    (r"Fatal error:.+on line \d+", "PHP fatal error"),
    (r"Stack Trace:.*at System\.", "ASP.NET stack trace"),
    (r"SQLSTATE\[", "Database error (PDO)"),
    (r"pg_query\(\):", "PostgreSQL error"),
    (r"mysql_.*error", "MySQL error exposed"),
    (r"ORA-\d{5}", "Oracle DB error"),
    (r"Django Version:", "Django debug page"),
    (r"DEBUG.*True", "Debug mode indicator"),
    (r'"debug"\s*:\s*true', "Debug flag in JSON"),
    (r"WP_DEBUG", "WordPress debug mode"),
]

# Paths que provocan errores.
ERROR_TRIGGER_PATHS = [
    "/a%00b",                    # Null byte
    "/../../etc/passwd",         # Path traversal (should be blocked)
    "/%27%22",                   # Quote injection
    "/undefined",                # Common 404
    "/api/v1/nonexistent",       # API 404
    "/?id=1'",                   # SQLi probe (error trigger)
]


class InsecureDesignScanner(BaseScanner):
    name = "insecure_design"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        base = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base += f":{target.port}"

        # Check prefetched response for info disclosure.
        comments = self._check_html_comments(context.body_text)
        errors_in_main = self._check_error_patterns(context.body_text)

        # Active: trigger errors and check responses.
        error_disclosures = self._probe_errors(base)

        # Active: basic rate limit check.
        rate_limited = self._check_rate_limiting(base)

        result.raw = {
            "html_comments_sensitive": len(comments),
            "errors_in_main_page": len(errors_in_main),
            "error_disclosures": len(error_disclosures),
            "rate_limiting_detected": rate_limited,
        }

        # --- Stack traces / debug info ---
        for disc in error_disclosures:
            result.findings.append(self.finding(
                category=Category.DESIGN,
                severity=Severity.MEDIUM,
                title=f"Information disclosure: {disc['type']} (A04)",
                description=(
                    f"Al solicitar '{disc['path']}' el servidor reveló "
                    f"información interna ({disc['type']}). "
                    "Los atacantes usan esto para mapear la tecnología interna."
                ),
                evidence={"path": disc["path"], "type": disc["type"],
                          "snippet": disc.get("snippet", "")[:300]},
                recommendation=(
                    "Configura páginas de error genéricas en producción. "
                    "Desactiva debug mode y stack traces."
                ),
                reference_url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
            ))

        # Errors in main page.
        for err in errors_in_main:
            result.findings.append(self.finding(
                category=Category.DESIGN,
                severity=Severity.MEDIUM,
                title=f"Información de debug en página principal: {err['type']} (A04)",
                description=(
                    f"La página principal contiene patrones de {err['type']}. "
                    "Esto indica que el modo debug puede estar activo en producción."
                ),
                evidence=err,
                recommendation="Desactiva debug mode en producción.",
                reference_url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
            ))

        # --- Sensitive HTML comments ---
        if comments:
            result.findings.append(self.finding(
                category=Category.DESIGN,
                severity=Severity.LOW,
                title=f"{len(comments)} comentarios HTML con información sensible (A04)",
                description=(
                    "Se encontraron comentarios HTML que revelan información interna "
                    "como TODOs, credenciales, rutas internas o notas de desarrollo."
                ),
                evidence={"comments": comments[:10]},
                recommendation=(
                    "Elimina comentarios HTML con información interna antes de "
                    "desplegar a producción."
                ),
            ))

        # --- Rate limiting ---
        if not rate_limited:
            result.findings.append(self.finding(
                category=Category.DESIGN,
                severity=Severity.LOW,
                title="No se detectó rate limiting (A04)",
                description=(
                    "Se enviaron 10 requests rápidos y ninguno fue bloqueado. "
                    "Sin rate limiting, el servidor es vulnerable a brute force "
                    "y credential stuffing."
                ),
                recommendation=(
                    "Implementa rate limiting por IP/usuario. "
                    "Ejemplo: django-ratelimit, nginx limit_req_zone, "
                    "o WAF (Cloudflare, AWS WAF)."
                ),
                reference_url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
            ))

        if not error_disclosures and not errors_in_main and not comments \
                and rate_limited:
            result.findings.append(self.finding(
                category=Category.DESIGN,
                severity=Severity.INFO,
                title="No se detectaron fallos de diseño inseguro (A04)",
                description="Error handling, rate limiting y comments verificados.",
            ))

        return result

    def _check_error_patterns(self, text: str) -> list[dict]:
        """Busca patrones de error/debug en texto."""
        found = []
        for pattern, ptype in ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                found.append({
                    "type": ptype,
                    "snippet": match.group(0)[:200],
                })
        return found

    def _probe_errors(self, base: str) -> list[dict]:
        """Envía requests diseñados para provocar errores reveladores."""
        disclosures = []
        for path in ERROR_TRIGGER_PATHS:
            try:
                resp = requests.get(
                    base + path,
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=True,
                )
                if resp.status_code >= 400:
                    found = self._check_error_patterns(resp.text)
                    for f in found:
                        f["path"] = path
                        disclosures.append(f)
            except requests.RequestException:
                continue
        return disclosures

    def _check_html_comments(self, html: str) -> list[str]:
        """Extrae comentarios HTML que podrían contener info sensible."""
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        sensitive_keywords = [
            "todo", "fixme", "hack", "password", "secret", "api_key",
            "token", "credential", "debug", "admin", "internal",
            "database", "config", "temp", "remove",
        ]
        suspicious = []
        for c in comments:
            c_clean = c.strip()
            if len(c_clean) < 5:
                continue
            c_lower = c_clean.lower()
            if any(kw in c_lower for kw in sensitive_keywords):
                suspicious.append(c_clean[:200])
        return suspicious

    def _check_rate_limiting(self, base: str) -> bool:
        """Envía 10 requests rápidos para verificar rate limiting."""
        blocked = False
        for _ in range(10):
            try:
                resp = requests.get(
                    base + "/",
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=True,
                )
                if resp.status_code == 429:
                    blocked = True
                    break
            except requests.RequestException:
                break
            time.sleep(0.05)
        return blocked
