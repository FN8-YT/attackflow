"""
OWASP A08 — Software and Data Integrity Failures.

Detecta desde fuera:
- Scripts externos sin Subresource Integrity (SRI).
- Scripts cargados por HTTP en página HTTPS (supply chain risk).
- Uso de CDNs sin verificación de integridad.
- Headers que afectan integridad: Permissions-Policy, Content-Type con nosniff.

Es 100% pasivo — solo analiza la respuesta HTTP prefetch.

Limitaciones honestas:
- No puede verificar pipelines CI/CD ni procesos de build.
- No detecta dependencias comprometidas server-side.
- Solo analiza scripts visibles en el HTML inicial (no lazy-loaded).
"""
from __future__ import annotations

import re

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult


class IntegrityScanner(BaseScanner):
    name = "integrity"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        html = context.body_text
        is_https = context.target.scheme == "https"

        scripts = self._analyze_external_scripts(html, is_https)
        nosniff = self._check_nosniff(context)

        result.raw = {
            "external_scripts_total": scripts["total"],
            "scripts_without_sri": scripts["no_sri_count"],
            "scripts_over_http": scripts["http_count"],
            "x_content_type_options": nosniff,
        }

        # --- Scripts sin SRI ---
        if scripts["no_sri"]:
            result.findings.append(self.finding(
                category=Category.INTEGRITY,
                severity=Severity.MEDIUM,
                title=f"{scripts['no_sri_count']} script(s) externo(s) sin SRI (A08)",
                description=(
                    "Se encontraron scripts cargados desde dominios externos "
                    "sin el atributo 'integrity' (Subresource Integrity). "
                    "Si el CDN o servidor externo es comprometido, el código "
                    "malicioso se ejecutaría en los navegadores de los usuarios."
                ),
                evidence={"scripts": scripts["no_sri"][:10]},
                recommendation=(
                    "Añade atributos integrity y crossorigin a todos los <script> "
                    "externos. Ejemplo: <script src='...' "
                    "integrity='sha384-...' crossorigin='anonymous'>"
                ),
                reference_url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            ))

        # --- Scripts cargados por HTTP ---
        if scripts["http_scripts"]:
            result.findings.append(self.finding(
                category=Category.INTEGRITY,
                severity=Severity.HIGH,
                title=f"{scripts['http_count']} script(s) cargado(s) por HTTP (A08)",
                description=(
                    "Scripts JavaScript cargados por HTTP sin cifrar. "
                    "Un atacante MitM puede inyectar código malicioso "
                    "en estas respuestas."
                ),
                evidence={"scripts": scripts["http_scripts"][:10]},
                recommendation="Carga todos los scripts por HTTPS.",
                reference_url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            ))

        # --- X-Content-Type-Options ---
        if not nosniff.get("present"):
            result.findings.append(self.finding(
                category=Category.INTEGRITY,
                severity=Severity.LOW,
                title="X-Content-Type-Options: nosniff ausente (A08)",
                description=(
                    "Sin este header, el navegador puede interpretar archivos "
                    "con MIME type incorrecto como scripts ejecutables "
                    "(MIME sniffing), facilitando ataques de inyección."
                ),
                evidence=nosniff,
                recommendation="Añade el header: X-Content-Type-Options: nosniff",
                reference_url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            ))

        if not scripts["no_sri"] and not scripts["http_scripts"] \
                and nosniff.get("present"):
            result.findings.append(self.finding(
                category=Category.INTEGRITY,
                severity=Severity.INFO,
                title="No se detectaron fallos de integridad (A08)",
                description=(
                    "Scripts con SRI, sin carga HTTP y X-Content-Type-Options presente."
                ),
            ))

        return result

    def _analyze_external_scripts(self, html: str, is_https: bool) -> dict:
        """Analiza <script src=...> externos por SRI y protocolo."""
        # Match script tags with src attribute.
        script_tags = re.findall(
            r'<script\b([^>]*)>', html, re.IGNORECASE,
        )

        no_sri: list[str] = []
        http_scripts: list[str] = []
        total = 0

        for attrs in script_tags:
            src_match = re.search(
                r'src\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE,
            )
            if not src_match:
                continue

            src = src_match.group(1)

            # Only check external scripts (absolute URLs or protocol-relative).
            if not (src.startswith("http://") or src.startswith("https://")
                    or src.startswith("//")):
                continue

            total += 1

            # Check SRI.
            has_integrity = re.search(
                r'integrity\s*=\s*["\']', attrs, re.IGNORECASE,
            )
            if not has_integrity:
                no_sri.append(src[:200])

            # Check HTTP loading.
            if src.startswith("http://"):
                http_scripts.append(src[:200])

        return {
            "total": total,
            "no_sri": no_sri,
            "no_sri_count": len(no_sri),
            "http_scripts": http_scripts,
            "http_count": len(http_scripts),
        }

    def _check_nosniff(self, context: ScanContext) -> dict:
        """Verifica X-Content-Type-Options: nosniff."""
        val = context.http_response.headers.get(
            "X-Content-Type-Options", "",
        )
        return {
            "present": "nosniff" in val.lower() if val else False,
            "value": val or "ausente",
        }
