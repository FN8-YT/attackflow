"""
Scanner de enumeración de subdominios vía crt.sh.

Consulta la base de datos de Certificate Transparency para descubrir
subdominios emitidos para el dominio objetivo. Es 100 % pasivo — solo
lee registros públicos de certificados.

Esto es una de las primeras cosas que hace un bug bounty hunter:
ampliar la superficie de ataque descubriendo hosts ocultos.
"""
from __future__ import annotations

import logging

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"
CRT_SH_TIMEOUT = 20


class SubdomainScanner(BaseScanner):
    name = "subdomains"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        domain = context.target.hostname

        # Extraer dominio base (ej: sub.example.com → example.com).
        parts = domain.split(".")
        if len(parts) > 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        subdomains: set[str] = set()
        try:
            resp = requests.get(
                CRT_SH_URL.format(domain=base_domain),
                timeout=CRT_SH_TIMEOUT,
                headers={"User-Agent": "SecurityAuditBot/0.1"},
            )
            if resp.status_code == 200 and resp.text.strip():
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    # crt.sh puede devolver wildcards y multilínea.
                    for line in name.split("\n"):
                        clean = line.strip().lstrip("*.")
                        if clean and clean.endswith(base_domain):
                            subdomains.add(clean.lower())
        except (requests.RequestException, ValueError) as exc:
            logger.warning("crt.sh query failed for %s: %s", base_domain, exc)
            result.raw = {"error": str(exc)}
            return result

        # Eliminar el propio dominio base del listado.
        subdomains.discard(base_domain)
        sorted_subs = sorted(subdomains)

        result.raw = {
            "base_domain": base_domain,
            "count": len(sorted_subs),
            "subdomains": sorted_subs[:200],  # Limitar para no explotar raw_data
        }

        if sorted_subs:
            result.findings.append(
                self.finding(
                    category=Category.RECON,
                    severity=Severity.INFO,
                    title=f"{len(sorted_subs)} subdominios descubiertos vía CT logs",
                    description=(
                        f"Se encontraron {len(sorted_subs)} subdominios únicos "
                        f"para {base_domain} en registros de Certificate Transparency."
                    ),
                    evidence={
                        "count": len(sorted_subs),
                        "sample": sorted_subs[:30],
                    },
                    recommendation=(
                        "Revisa que todos los subdominios están intencionalmente "
                        "expuestos. Los subdominios olvidados suelen tener software "
                        "desactualizado y son un vector de ataque frecuente."
                    ),
                )
            )

            # Alertar si hay muchos (superficie de ataque amplia).
            if len(sorted_subs) > 50:
                result.findings.append(
                    self.finding(
                        category=Category.RECON,
                        severity=Severity.LOW,
                        title="Superficie de ataque amplia: más de 50 subdominios",
                        description=(
                            f"Se descubrieron {len(sorted_subs)} subdominios. "
                            "Una superficie amplia incrementa la probabilidad de "
                            "encontrar servicios expuestos involuntariamente."
                        ),
                        recommendation=(
                            "Audita periódicamente los subdominios activos. "
                            "Desactiva los que ya no se usen."
                        ),
                    )
                )
        else:
            result.findings.append(
                self.finding(
                    category=Category.RECON,
                    severity=Severity.INFO,
                    title="No se encontraron subdominios adicionales",
                    description=(
                        f"No se hallaron subdominios extra para {base_domain} "
                        "en los registros de Certificate Transparency."
                    ),
                )
            )

        return result
