"""
Scanner de XSS reflejado.

MODO ACTIVO: inyecta payloads benignos en parámetros de la URL y
comprueba si se reflejan sin sanitizar en la respuesta.

Solo se ejecuta en modo 'active'. Los payloads son inofensivos
(no intentan ejecutar JS real, solo detectar reflexión).

Estrategia:
1. Identificar parámetros de la URL objetivo.
2. Si no hay parámetros, probar con parámetros comunes (q, search, id, etc.).
3. Inyectar un canario HTML único y ver si aparece sin encodear.
"""
from __future__ import annotations

import logging
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

# Parámetros comunes que suelen reflejar input.
COMMON_PARAMS = ("q", "search", "query", "s", "keyword", "id", "page", "name", "redirect", "url", "next", "callback")

# Payloads canario — no ejecutan JS, solo detectan reflexión de HTML.
CANARY_TAG = "sa1x{nonce}"
PAYLOADS = [
    '<sa1x{nonce}>',
    '"sa1x{nonce}',
    "'sa1x{nonce}",
    "<img src=x onerror=sa1x{nonce}>",
]

XSS_TIMEOUT = 10


class XssScanner(BaseScanner):
    name = "xss"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        parsed = urlparse(target.url)

        # Recoger parámetros existentes o probar con comunes.
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        if existing_params:
            params_to_test = list(existing_params.keys())[:5]
        else:
            params_to_test = list(COMMON_PARAMS[:6])

        nonce = secrets.token_hex(4)
        reflected: list[dict] = []
        tested = 0

        for param in params_to_test:
            for payload_tpl in PAYLOADS:
                payload = payload_tpl.format(nonce=nonce)
                test_params = dict(existing_params)
                test_params[param] = [payload]

                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(test_params, doseq=True),
                    "",
                ))

                tested += 1
                try:
                    resp = requests.get(
                        test_url,
                        timeout=XSS_TIMEOUT,
                        allow_redirects=True,
                        headers={"User-Agent": "SecurityAuditBot/0.1"},
                    )
                    body = resp.text
                    # Comprobar si el canario se refleja sin encodear.
                    canary = f"sa1x{nonce}"
                    if canary in body and payload in body:
                        reflected.append({
                            "param": param,
                            "payload": payload,
                            "reflected_in": "body",
                            "status_code": resp.status_code,
                        })
                        break  # Un hit por param es suficiente.
                except requests.RequestException:
                    continue

        result.raw = {
            "params_tested": params_to_test,
            "payloads_sent": tested,
            "reflections_found": len(reflected),
        }

        if reflected:
            for ref in reflected:
                result.findings.append(
                    self.finding(
                        category=Category.VULNS,
                        severity=Severity.HIGH,
                        title=f"Posible XSS reflejado en parámetro '{ref['param']}'",
                        description=(
                            f"El parámetro '{ref['param']}' refleja input HTML "
                            "sin sanitizar en la respuesta. Esto puede permitir "
                            "inyección de JavaScript (Cross-Site Scripting)."
                        ),
                        evidence=ref,
                        recommendation=(
                            "Sanitiza/encodea toda salida de datos del usuario con "
                            "HTML entity encoding. Implementa Content-Security-Policy "
                            "para mitigar el impacto."
                        ),
                        reference_url="https://owasp.org/www-community/attacks/xss/",
                    )
                )
        else:
            result.findings.append(
                self.finding(
                    category=Category.VULNS,
                    severity=Severity.INFO,
                    title="No se detectó XSS reflejado",
                    description=(
                        f"Se probaron {tested} payloads en {len(params_to_test)} "
                        "parámetros sin encontrar reflexiones sin sanitizar."
                    ),
                )
            )

        return result
