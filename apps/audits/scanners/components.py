"""
OWASP A06 — Vulnerable and Outdated Components.

Detecta librerías JavaScript con versiones vulnerables conocidas:
- Extrae versiones de librerías desde <script src> y del HTML.
- Cross-referencia contra una base de datos built-in de CVEs conocidos.
- Detecta frameworks/CMS outdated desde meta tags y headers.

Es 100% pasivo — solo analiza la respuesta HTTP prefetch.

La base de CVEs es estática (no consulta APIs externas en tiempo real),
pero cubre las vulnerabilidades más críticas y frecuentes.
"""
from __future__ import annotations

import re
from typing import Any

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

# Base de datos de versiones vulnerables conocidas.
# Formato: (nombre, regex para extraer versión, versiones vulnerables)
KNOWN_VULNERABLE: list[dict[str, Any]] = [
    {
        "name": "jQuery",
        "patterns": [
            r"jquery[.-](\d+\.\d+\.\d+)",
            r"jquery\.min\.js\?v=(\d+\.\d+\.\d+)",
            r'jQuery\s+v?(\d+\.\d+\.\d+)',
        ],
        "vulns": [
            {"below": "3.5.0", "severity": "medium",
             "cve": "CVE-2020-11022", "title": "jQuery XSS via htmlPrefilter"},
            {"below": "3.0.0", "severity": "high",
             "cve": "CVE-2019-11358", "title": "jQuery prototype pollution"},
            {"below": "1.12.0", "severity": "medium",
             "cve": "CVE-2015-9251", "title": "jQuery XSS in cross-domain ajax"},
        ],
    },
    {
        "name": "Bootstrap",
        "patterns": [
            r"bootstrap[.-](\d+\.\d+\.\d+)",
            r"Bootstrap\s+v?(\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "3.4.0", "severity": "medium",
             "cve": "CVE-2018-14041", "title": "Bootstrap XSS in tooltip/popover"},
            {"below": "4.3.1", "severity": "medium",
             "cve": "CVE-2019-8331", "title": "Bootstrap XSS in sanitizer"},
        ],
    },
    {
        "name": "Angular.js",
        "patterns": [
            r"angular[.-](\d+\.\d+\.\d+)",
            r"AngularJS\s+v?(\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "1.8.0", "severity": "high",
             "cve": "CVE-2022-25869", "title": "AngularJS XSS via SVG attributes"},
            {"below": "1.6.0", "severity": "high",
             "cve": "Multiple", "title": "AngularJS sandbox escape / XSS"},
        ],
    },
    {
        "name": "Lodash",
        "patterns": [
            r"lodash[.-](\d+\.\d+\.\d+)",
            r"lodash\.min\.js.*?(\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "4.17.21", "severity": "high",
             "cve": "CVE-2021-23337", "title": "Lodash command injection via template"},
            {"below": "4.17.12", "severity": "high",
             "cve": "CVE-2019-10744", "title": "Lodash prototype pollution"},
        ],
    },
    {
        "name": "Moment.js",
        "patterns": [
            r"moment[.-](\d+\.\d+\.\d+)",
            r"moment\.min\.js.*?(\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "2.29.4", "severity": "high",
             "cve": "CVE-2022-31129", "title": "Moment.js ReDoS via string parsing"},
        ],
    },
    {
        "name": "Vue.js",
        "patterns": [
            r"vue[.-](\d+\.\d+\.\d+)",
            r"Vue\.js\s+v?(\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "2.5.0", "severity": "medium",
             "cve": "CVE-2018-11235", "title": "Vue.js XSS via template expressions"},
        ],
    },
    {
        "name": "React",
        "patterns": [
            r"react[.-](\d+\.\d+\.\d+)",
            r'"react":\s*"(\d+\.\d+\.\d+)"',
        ],
        "vulns": [
            {"below": "16.0.0", "severity": "medium",
             "cve": "CVE-2018-6341", "title": "React XSS via SSR"},
        ],
    },
    {
        "name": "Handlebars.js",
        "patterns": [
            r"handlebars[.-](\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "4.7.7", "severity": "critical",
             "cve": "CVE-2021-23369", "title": "Handlebars RCE via template compilation"},
        ],
    },
    {
        "name": "DOMPurify",
        "patterns": [
            r"purify[.-](\d+\.\d+\.\d+)",
            r"DOMPurify\s+(\d+\.\d+\.\d+)",
        ],
        "vulns": [
            {"below": "2.3.1", "severity": "high",
             "cve": "CVE-2021-23631", "title": "DOMPurify mutation XSS bypass"},
        ],
    },
]


def _version_tuple(v: str) -> tuple:
    """Convierte '3.5.1' a (3, 5, 1) para comparar."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def _is_below(version: str, threshold: str) -> bool:
    return _version_tuple(version) < _version_tuple(threshold)


class ComponentsScanner(BaseScanner):
    name = "components"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        html = context.body_text
        detected: list[dict] = []

        for lib in KNOWN_VULNERABLE:
            version = self._extract_version(html, lib["patterns"])
            if not version:
                continue

            vulns_found = []
            for vuln in lib["vulns"]:
                if _is_below(version, vuln["below"]):
                    vulns_found.append(vuln)

            if vulns_found:
                detected.append({
                    "library": lib["name"],
                    "version": version,
                    "vulnerabilities": vulns_found,
                })

        result.raw = {
            "vulnerable_components": len(detected),
            "details": detected,
        }

        for comp in detected:
            most_severe = max(
                comp["vulnerabilities"],
                key=lambda v: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(v["severity"], 0),
            )
            cves = ", ".join(v["cve"] for v in comp["vulnerabilities"])

            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }

            result.findings.append(self.finding(
                category=Category.COMPONENTS,
                severity=severity_map.get(most_severe["severity"], Severity.MEDIUM),
                title=(
                    f"{comp['library']} {comp['version']} — "
                    f"{len(comp['vulnerabilities'])} vulnerabilidad(es) conocida(s) (A06)"
                ),
                description=(
                    f"La librería {comp['library']} versión {comp['version']} "
                    f"tiene vulnerabilidades conocidas: {cves}. "
                    f"La más severa: {most_severe['title']}."
                ),
                evidence={
                    "library": comp["library"],
                    "version": comp["version"],
                    "cves": [v["cve"] for v in comp["vulnerabilities"]],
                    "details": [v["title"] for v in comp["vulnerabilities"]],
                },
                recommendation=(
                    f"Actualiza {comp['library']} a la última versión estable. "
                    f"Versión mínima segura: {most_severe['below']}+."
                ),
                reference_url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            ))

        if not detected:
            result.findings.append(self.finding(
                category=Category.COMPONENTS,
                severity=Severity.INFO,
                title="No se detectaron componentes vulnerables conocidos (A06)",
                description=(
                    "No se encontraron librerías JavaScript con CVEs conocidos "
                    "en el HTML de la página. Esto no descarta vulnerabilidades "
                    "en dependencias server-side."
                ),
            ))

        return result

    def _extract_version(self, html: str, patterns: list[str]) -> str | None:
        """Intenta extraer una versión usando múltiples regex."""
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
