"""
Cálculo del score de seguridad.

Filosofía:
- Partimos de 100 y restamos puntos ponderados por severidad.
- Los pesos viven aquí, aislados. Cambiarlos no toca ni modelos ni
  scanners: re-puntuar un audit histórico es literalmente correr esta
  función contra los findings ya guardados.
- Nunca bajamos de 0.
- INFO no penaliza: son datos puramente informativos.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from apps.audits.models import Category, Severity

SEVERITY_WEIGHTS: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 12,
    Severity.CRITICAL: 25,
}


class FindingLike(Protocol):
    severity: str
    category: str


def compute_score(findings: Iterable[FindingLike]) -> int:
    """Devuelve un entero 0..100."""
    penalty = 0
    for f in findings:
        penalty += SEVERITY_WEIGHTS.get(f.severity, 0)
    return max(0, min(100, 100 - penalty))


def score_breakdown(findings: Iterable[FindingLike]) -> dict[str, dict]:
    """
    Devuelve un desglose por categoría con su score parcial.
    Útil para un radar chart o tabla resumen en el informe.
    """
    categories = [c.value for c in Category]
    totals = {cat: 0 for cat in categories}
    counts = {
        cat: {sev.value: 0 for sev in Severity} for cat in categories
    }

    for f in findings:
        if f.category not in totals:
            continue
        totals[f.category] += SEVERITY_WEIGHTS.get(f.severity, 0)
        counts[f.category][f.severity] += 1

    return {
        cat: {
            "score": max(0, 100 - totals[cat]),
            "counts": counts[cat],
        }
        for cat in categories
    }


def severity_band(score: int) -> str:
    """Nombre del 'tier' visual: útil para pintar colores en la UI."""
    if score >= 85:
        return "good"
    if score >= 60:
        return "warn"
    return "bad"
