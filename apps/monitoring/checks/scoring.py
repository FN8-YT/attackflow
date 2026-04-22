"""
Security Score — puntuación 0-100 del estado de seguridad de un target.

Basado en:
- Presencia/ausencia de security headers (hasta 65 puntos)
- Estado del certificado SSL (hasta 20 puntos)
- Paths sensibles expuestos (hasta 30 puntos de penalización, capped)

Clasificación:
  90-100 → A  (verde)    Todo correcto
  75-89  → B  (verde dim) Buena postura, pequeñas mejoras
  60-74  → C  (naranja)  Deficiencias notables
  40-59  → D  (rojo dim) Configuración peligrosa
  0-39   → F  (rojo)     Crítico
"""
from __future__ import annotations

# (header_lower, puntos_deducidos_si_falta)
HEADER_WEIGHTS: list[tuple[str, int]] = [
    ("content-security-policy",        20),
    ("strict-transport-security",      15),
    ("x-content-type-options",         10),
    ("x-frame-options",                10),
    ("referrer-policy",                 5),
    ("permissions-policy",              5),
]

# Penalización por path sensible expuesto
SEVERITY_DEDUCTIONS: dict[str, int] = {
    "critical": 15,
    "high":     8,
    "medium":   3,
    "info":     0,
}


def calculate_security_score(
    headers_snapshot: dict,
    ssl_expiry_days: int | None,
    sensitive_paths_found: list[dict],
) -> int:
    """
    Calcula la puntuación de seguridad (0-100).

    Args:
        headers_snapshot: Dict de security headers capturados.
        ssl_expiry_days:  Días hasta expiración del SSL (None = sin SSL).
        sensitive_paths_found: Lista de paths sensibles encontrados.

    Returns:
        Entero entre 0 y 100.
    """
    score = 100
    present = {k.lower() for k in (headers_snapshot or {})}

    # Headers
    for header, deduction in HEADER_WEIGHTS:
        if header not in present:
            score -= deduction

    # SSL
    if ssl_expiry_days is None:
        score -= 20          # sin SSL
    elif ssl_expiry_days <= 0:
        score -= 20          # expirado
    elif ssl_expiry_days <= 7:
        score -= 15          # crítico
    elif ssl_expiry_days <= 30:
        score -= 8           # warning

    # Paths sensibles (capped a -30)
    path_deduction = 0
    for path in (sensitive_paths_found or []):
        path_deduction += SEVERITY_DEDUCTIONS.get(path.get("severity", "info"), 0)
    score -= min(path_deduction, 30)

    return max(0, min(100, score))


def score_grade(score: int) -> tuple[str, str]:
    """
    Retorna (letra, color_css) para un score dado.

    Returns:
        Tuple (grade, color) donde color es una variable CSS del tema.
    """
    if score >= 90:
        return "A", "var(--green-bright)"
    if score >= 75:
        return "B", "var(--green)"
    if score >= 60:
        return "C", "var(--orange)"
    if score >= 40:
        return "D", "#e07000"
    return "F", "var(--red)"
