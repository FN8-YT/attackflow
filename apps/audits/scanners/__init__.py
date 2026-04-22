"""
Paquete de scanners.

Cada scanner implementa BaseScanner y se registra en SCANNER_REGISTRY,
que contiene la metadata para el UI (label, descripción, tier, default).

Tiers:
- base:   siempre disponible, cualquier modo de escaneo.
- active: envía payloads de prueba, requiere modo de escaneo 'active'.

No existe gating por plan: todos los scanners son accesibles para
cualquier usuario autenticado. El único requisito para los scanners
de tier 'active' es seleccionar el modo de escaneo activo.

El orquestador y el formulario usan get_available_scanners() y
get_scanners_for_audit() para selección basada en modo + elección del usuario.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .base import BaseScanner, FindingData, ScanContext, ScanResult
from .dns import DnsScanner
from .headers import HttpHeadersScanner
from .misconfig import MisconfigScanner
from .ports import PortsScanner
from .sqli import SqliScanner
from .subdomains import SubdomainScanner
from .tech import TechScanner
from .tls import TlsScanner
from .vulns import VulnsScanner
from .xss import XssScanner

# OWASP Top 10 scanners.
from .broken_access import BrokenAccessScanner
from .crypto import CryptoScanner
from .insecure_design import InsecureDesignScanner
from .components import ComponentsScanner
from .auth_failures import AuthFailuresScanner
from .integrity import IntegrityScanner
from .logging_exposure import LoggingExposureScanner
from .ssrf_scan import SsrfScanner

# JS Client-Side Analysis scanners.
from .js_analysis import JSAnalysisScanner
from .js_secrets import JSSecretsScanner
from .js_endpoints import JSEndpointsScanner

# Nuclei — vulnerability scanner externo
from .nuclei_scanner import NucleiScanner


# ── Scanner metadata ──────────────────────────────────────────
@dataclass(frozen=True)
class ScannerMeta:
    """Metadata de un scanner para UI y selección."""

    key: str                # ID único (coincide con scanner.name)
    label: str              # Nombre legible para el usuario
    description: str        # Descripción corta de qué hace
    tier: str               # 'base' | 'active'
    default: bool           # ¿Seleccionado por defecto?
    icon: str = ""          # Emoji o símbolo para el UI (opcional)


# ── Registry central ─────────────────────────────────────────
# Orden = orden de ejecución. Cada entrada vincula metadata + instancia.

SCANNER_REGISTRY: list[dict[str, Any]] = [
    # ── BASE (disponibles siempre) ─────────────────────────
    {
        "meta": ScannerMeta(
            key="dns",
            label="DNS Resolution",
            description="Resolución DNS, registros A/AAAA/MX/NS y validación del dominio.",
            tier="base",
            default=True,
            icon="[DNS]",
        ),
        "instance": DnsScanner(),
    },
    {
        "meta": ScannerMeta(
            key="tls",
            label="SSL/TLS Analysis",
            description="Certificado SSL, cadena de confianza, expiración y protocolos.",
            tier="base",
            default=True,
            icon="[TLS]",
        ),
        "instance": TlsScanner(),
    },
    {
        "meta": ScannerMeta(
            key="http_headers",
            label="HTTP Security Headers",
            description="Análisis de cabeceras de seguridad: CSP, HSTS, X-Frame-Options, etc.",
            tier="base",
            default=True,
            icon="[HDR]",
        ),
        "instance": HttpHeadersScanner(),
    },
    {
        "meta": ScannerMeta(
            key="vulns",
            label="Vulnerability Detection",
            description="Detección de vulnerabilidades conocidas y exposición de información.",
            tier="base",
            default=True,
            icon="[VLN]",
        ),
        "instance": VulnsScanner(),
    },
    {
        "meta": ScannerMeta(
            key="ports",
            label="Port Scanning",
            description="Escaneo de puertos TCP abiertos con nmap (top 100 ports).",
            tier="base",
            default=True,
            icon="[PRT]",
        ),
        "instance": PortsScanner(),
    },
    {
        "meta": ScannerMeta(
            key="subdomains",
            label="Subdomain Enumeration",
            description="Enumeración de subdominios vía Certificate Transparency (crt.sh).",
            tier="base",
            default=True,
            icon="[SUB]",
        ),
        "instance": SubdomainScanner(),
    },
    {
        "meta": ScannerMeta(
            key="tech",
            label="Technology Fingerprinting",
            description="Identificación de tecnologías del servidor: frameworks, CMS, lenguajes.",
            tier="base",
            default=True,
            icon="[TCH]",
        ),
        "instance": TechScanner(),
    },
    {
        "meta": ScannerMeta(
            key="crypto",
            label="Cryptographic Failures (A02)",
            description="Cookies inseguras, mixed content, HSTS y formularios HTTP.",
            tier="base",
            default=True,
            icon="[A02]",
        ),
        "instance": CryptoScanner(),
    },
    {
        "meta": ScannerMeta(
            key="components",
            label="Vulnerable Components (A06)",
            description="Librerías JavaScript con CVEs conocidos (jQuery, Bootstrap, etc.).",
            tier="base",
            default=True,
            icon="[A06]",
        ),
        "instance": ComponentsScanner(),
    },
    {
        "meta": ScannerMeta(
            key="integrity",
            label="Software Integrity (A08)",
            description="Scripts sin SRI, carga HTTP y protección de MIME type.",
            tier="base",
            default=True,
            icon="[A08]",
        ),
        "instance": IntegrityScanner(),
    },
    # ── ACTIVE (requieren modo de escaneo activo) ──────────
    {
        "meta": ScannerMeta(
            key="xss",
            label="XSS Detection",
            description="Detección de Cross-Site Scripting reflejado con payloads canary.",
            tier="active",
            default=True,
            icon="[XSS]",
        ),
        "instance": XssScanner(),
    },
    {
        "meta": ScannerMeta(
            key="sqli",
            label="SQL Injection Detection",
            description="Detección de SQL Injection basada en errores de base de datos.",
            tier="active",
            default=True,
            icon="[SQL]",
        ),
        "instance": SqliScanner(),
    },
    {
        "meta": ScannerMeta(
            key="misconfig",
            label="Misconfiguration Detection",
            description="Archivos expuestos, directory listing y open redirect.",
            tier="active",
            default=True,
            icon="[CFG]",
        ),
        "instance": MisconfigScanner(),
    },
    {
        "meta": ScannerMeta(
            key="broken_access",
            label="Broken Access Control (A01)",
            description="CORS misconfiguration, paneles admin expuestos, métodos HTTP peligrosos.",
            tier="active",
            default=True,
            icon="[A01]",
        ),
        "instance": BrokenAccessScanner(),
    },
    {
        "meta": ScannerMeta(
            key="insecure_design",
            label="Insecure Design (A04)",
            description="Stack traces, debug mode, rate limiting y comentarios sensibles.",
            tier="active",
            default=True,
            icon="[A04]",
        ),
        "instance": InsecureDesignScanner(),
    },
    {
        "meta": ScannerMeta(
            key="auth_failures",
            label="Authentication Failures (A07)",
            description="Login sin CSRF, account enumeration, session fixation, login HTTP.",
            tier="active",
            default=True,
            icon="[A07]",
        ),
        "instance": AuthFailuresScanner(),
    },
    {
        "meta": ScannerMeta(
            key="logging_exposure",
            label="Logging & Monitoring (A09)",
            description="Endpoints de logs/debug expuestos, headers de reporting.",
            tier="active",
            default=True,
            icon="[A09]",
        ),
        "instance": LoggingExposureScanner(),
    },
    {
        "meta": ScannerMeta(
            key="ssrf_scan",
            label="SSRF Detection (A10)",
            description="Open redirects, parámetros URL y cadenas de redirección.",
            tier="active",
            default=True,
            icon="[A10]",
        ),
        "instance": SsrfScanner(),
    },
    {
        "meta": ScannerMeta(
            key="nuclei",
            label="Nuclei — Vulnerability Scanner",
            description=(
                "Escaneo con 9000+ templates de ProjectDiscovery: CVEs, paneles expuestos, "
                "misconfigs, default credentials, y más. Severidad CRITICAL/HIGH/MEDIUM."
            ),
            tier="active",
            default=True,
            icon="[NUC]",
        ),
        "instance": NucleiScanner(),
    },
    {
        "meta": ScannerMeta(
            key="js_analysis",
            label="JS Security Analysis",
            description="Funciones peligrosas (eval, document.write), DOM XSS sinks y postMessage.",
            tier="active",
            default=True,
            icon="[JSA]",
        ),
        "instance": JSAnalysisScanner(),
    },
    {
        "meta": ScannerMeta(
            key="js_secrets",
            label="JS Secrets Detection",
            description="API keys, tokens, credenciales, debug flags y source maps en JavaScript.",
            tier="active",
            default=True,
            icon="[JSS]",
        ),
        "instance": JSSecretsScanner(),
    },
    {
        "meta": ScannerMeta(
            key="js_endpoints",
            label="JS Endpoint Discovery",
            description="Rutas API, endpoints ocultos, WebSockets y parámetros en JavaScript.",
            tier="active",
            default=True,
            icon="[JSE]",
        ),
        "instance": JSEndpointsScanner(),
    },
]


# ── Lookup rápido por key ─────────────────────────────────────
_REGISTRY_MAP: dict[str, dict[str, Any]] = {
    entry["meta"].key: entry for entry in SCANNER_REGISTRY
}

# Listas por tier.
BASE_SCANNERS: list[BaseScanner] = [
    e["instance"] for e in SCANNER_REGISTRY if e["meta"].tier == "base"
]
ACTIVE_SCANNERS: list[BaseScanner] = [
    e["instance"] for e in SCANNER_REGISTRY if e["meta"].tier == "active"
]
DEFAULT_SCANNERS = BASE_SCANNERS


# ── Funciones públicas ────────────────────────────────────────

def get_available_scanners(scan_mode: str) -> list[ScannerMeta]:
    """
    Devuelve la metadata de los scanners disponibles según el modo seleccionado.
    - Modo passive: solo tier 'base'.
    - Modo active:  tier 'base' + tier 'active'.
    """
    if scan_mode == "active":
        return [entry["meta"] for entry in SCANNER_REGISTRY]
    return [entry["meta"] for entry in SCANNER_REGISTRY if entry["meta"].tier == "base"]


def get_all_scanner_meta() -> list[ScannerMeta]:
    """Devuelve TODA la metadata del registry (para mostrar en el UI)."""
    return [entry["meta"] for entry in SCANNER_REGISTRY]


def get_scanners(scan_mode: str) -> list[BaseScanner]:
    """
    Devuelve instancias de scanners según el modo.
    Usada cuando NO hay selección personalizada del usuario.
    """
    if scan_mode == "active":
        return list(BASE_SCANNERS) + list(ACTIVE_SCANNERS)
    return list(BASE_SCANNERS)


def get_scanners_for_audit(
    scan_mode: str,
    selected_keys: list[str] | None = None,
) -> list[BaseScanner]:
    """
    Devuelve las instancias de scanners que se ejecutarán, filtradas por
    la selección del usuario y el modo de escaneo.

    Si selected_keys es None o vacío, ejecuta todos los disponibles para el modo.
    """
    if not selected_keys:
        return get_scanners(scan_mode)

    # Tiers permitidos según modo.
    allowed_tiers = {"base"}
    if scan_mode == "active":
        allowed_tiers.add("active")

    scanners: list[BaseScanner] = [
        entry["instance"]
        for key in selected_keys
        if (entry := _REGISTRY_MAP.get(key)) and entry["meta"].tier in allowed_tiers
    ]

    # Fallback: si la selección queda vacía, ejecutar base.
    return scanners or list(BASE_SCANNERS)


__all__ = [
    "BaseScanner",
    "FindingData",
    "ScanContext",
    "ScanResult",
    "ScannerMeta",
    "SCANNER_REGISTRY",
    "BASE_SCANNERS",
    "ACTIVE_SCANNERS",
    "DEFAULT_SCANNERS",
    "get_scanners",
    "get_scanners_for_audit",
    "get_available_scanners",
    "get_all_scanner_meta",
    "DnsScanner",
    "TlsScanner",
    "HttpHeadersScanner",
    "VulnsScanner",
    "PortsScanner",
    "SubdomainScanner",
    "TechScanner",
    "XssScanner",
    "SqliScanner",
    "MisconfigScanner",
    # OWASP Top 10
    "BrokenAccessScanner",
    "CryptoScanner",
    "InsecureDesignScanner",
    "ComponentsScanner",
    "AuthFailuresScanner",
    "IntegrityScanner",
    "LoggingExposureScanner",
    "SsrfScanner",
    # JS Client-Side Analysis
    "JSAnalysisScanner",
    "JSSecretsScanner",
    "JSEndpointsScanner",
    # Nuclei
    "NucleiScanner",
]
