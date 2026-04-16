"""
Contratos comunes a todos los scanners.

Strategy pattern:
- BaseScanner define la interfaz (método abstracto `run`).
- Cada scanner concreto implementa una única responsabilidad.
- El orquestador no conoce los detalles; solo llama a scanner.run(ctx).

Esto respeta Open/Closed: se añaden nuevos scanners sin tocar el core.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from apps.audits.validators import ScanTarget


@dataclass
class FindingData:
    """Finding en forma de DTO, antes de persistirlo en BD."""

    category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    reference_url: str = ""


@dataclass
class ScanContext:
    """
    Contexto compartido entre scanners.

    El orquestador hace una única petición HTTP al inicio y la comparte
    aquí. Los scanners que necesiten el body/headers lo consultan sin
    repetir la request (ahorro de tiempo y de tráfico contra el objetivo).
    """

    target: ScanTarget
    http_response: Optional[requests.Response] = None
    http_error: Optional[str] = None

    @property
    def has_http(self) -> bool:
        return self.http_response is not None

    @property
    def body_text(self) -> str:
        """Cuerpo HTML como string, o cadena vacía si no hay respuesta."""
        if self.http_response is None:
            return ""
        try:
            return self.http_response.text
        except Exception:
            return ""


@dataclass
class ScanResult:
    """Lo que devuelve cada scanner: raw (para debug) + findings."""

    raw: dict[str, Any] = field(default_factory=dict)
    findings: list[FindingData] = field(default_factory=list)


class BaseScanner(ABC):
    """Interfaz común. Name debe ser único y estable (se usa como clave en raw_data)."""

    name: str = "base"

    @abstractmethod
    def run(self, context: ScanContext) -> ScanResult:
        """Ejecuta el scanner y devuelve resultado estructurado."""

    # Helper para que los scanners hijos construyan findings sin verbosidad.
    @staticmethod
    def finding(
        *,
        category: str,
        severity: str,
        title: str,
        description: str,
        evidence: dict[str, Any] | None = None,
        recommendation: str = "",
        reference_url: str = "",
    ) -> FindingData:
        return FindingData(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence or {},
            recommendation=recommendation,
            reference_url=reference_url,
        )
