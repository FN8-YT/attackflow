"""
JS Client-Side Analysis — Dangerous Patterns & DOM XSS.

Detecta:
- Funciones peligrosas: eval(), Function(), document.write(), etc.
- DOM XSS sinks: innerHTML, outerHTML, insertAdjacentHTML.
- DOM XSS sources → sinks: document.URL/referrer/location en sinks.
- postMessage sin validación de origin.
- jQuery unsafe sinks: .html(), .append() con input dinámico.
- setTimeout/setInterval con strings (equivalente a eval).

Analiza tanto scripts inline como externos (fetch activo).

Cómo funciona:
1. El JSCollector extrae todos los scripts (inline + externos).
2. Se aplican patrones regex sobre cada fuente JS.
3. Cada match se contextualiza (línea, fragmento) para evidence.
4. Se clasifican por severidad según el tipo de sink y su contexto.

Limitaciones honestas:
- Análisis estático basado en regex, no un AST parser completo.
- No puede rastrear flujo de datos entre variables (taint analysis).
- Código minificado reduce la precisión del contexto.
- No analiza JS generado dinámicamente o cargado via import().
- Puede generar falsos positivos en código que sanitiza antes de usar sinks.
  → Cada hallazgo debe verificarse manualmente.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult
from ._js_collector import JSCollector, JSSource


@dataclass(frozen=True)
class _Pattern:
    """Un patrón de detección con metadata."""

    name: str
    regex: str
    severity: str
    title: str
    description: str
    recommendation: str
    flags: int = re.IGNORECASE


# ── Dangerous function patterns ──────────────────────────────

DANGEROUS_FUNCTIONS: list[_Pattern] = [
    _Pattern(
        name="eval",
        regex=r'\beval\s*\(',
        severity=Severity.HIGH,
        title="Uso de eval() detectado",
        description=(
            "eval() ejecuta código JavaScript arbitrario. Si algún dato "
            "controlado por el usuario llega a eval(), es Remote Code "
            "Execution en el navegador (DOM XSS)."
        ),
        recommendation=(
            "Elimina eval(). Usa JSON.parse() para datos JSON, "
            "window[funcName]() para llamadas dinámicas, o "
            "new Function() solo como último recurso con input validado."
        ),
    ),
    _Pattern(
        name="new_function",
        regex=r'\bnew\s+Function\s*\(',
        severity=Severity.HIGH,
        title="Uso de new Function() detectado",
        description=(
            "new Function() es equivalente a eval() — compila y ejecuta "
            "strings como código. Mismo riesgo de ejecución arbitraria."
        ),
        recommendation=(
            "Refactoriza para evitar generación dinámica de funciones. "
            "Si es indispensable, asegura que el input está hardcodeado "
            "o proviene de una fuente confiable."
        ),
    ),
    _Pattern(
        name="document_write",
        regex=r'\bdocument\.write(?:ln)?\s*\(',
        severity=Severity.MEDIUM,
        title="Uso de document.write() detectado",
        description=(
            "document.write() inserta HTML directamente en el DOM. "
            "Si el contenido incluye datos del usuario sin sanitizar, "
            "permite XSS. Además bloquea el parsing del navegador."
        ),
        recommendation=(
            "Usa DOM APIs seguras: textContent, createElement(), "
            "o un framework con auto-escaping (React, Vue, etc.)."
        ),
    ),
    _Pattern(
        name="setTimeout_string",
        regex=r'\bsetTimeout\s*\(\s*["\']',
        severity=Severity.MEDIUM,
        title="setTimeout() con string (eval implícito)",
        description=(
            "setTimeout('código', ms) es equivalente a eval('código'). "
            "El motor JS compila el string como código ejecutable."
        ),
        recommendation="Pasa una función en lugar de un string: setTimeout(fn, ms).",
    ),
    _Pattern(
        name="setInterval_string",
        regex=r'\bsetInterval\s*\(\s*["\']',
        severity=Severity.MEDIUM,
        title="setInterval() con string (eval implícito)",
        description=(
            "setInterval('código', ms) es equivalente a eval() repetido. "
            "Compila y ejecuta el string en cada intervalo."
        ),
        recommendation="Pasa una función en lugar de un string: setInterval(fn, ms).",
    ),
]


# ── DOM XSS sink patterns ────────────────────────────────────

DOM_XSS_SINKS: list[_Pattern] = [
    _Pattern(
        name="innerHTML",
        regex=r'\.innerHTML\s*[+]?=',
        severity=Severity.HIGH,
        title="Asignación a innerHTML detectada",
        description=(
            "innerHTML interpreta HTML completo incluyendo <script> y "
            "event handlers. Es el sink DOM XSS más explotado. "
            "Si el valor asignado contiene datos del usuario, es XSS."
        ),
        recommendation=(
            "Usa textContent para texto plano, o DOMPurify.sanitize() "
            "si necesitas insertar HTML controlado."
        ),
    ),
    _Pattern(
        name="outerHTML",
        regex=r'\.outerHTML\s*[+]?=',
        severity=Severity.HIGH,
        title="Asignación a outerHTML detectada",
        description=(
            "outerHTML reemplaza el elemento completo con HTML parseado. "
            "Mismo riesgo que innerHTML — permite inyección de scripts."
        ),
        recommendation="Usa DOM APIs seguras o DOMPurify para sanitizar.",
    ),
    _Pattern(
        name="insertAdjacentHTML",
        regex=r'\.insertAdjacentHTML\s*\(',
        severity=Severity.MEDIUM,
        title="Uso de insertAdjacentHTML() detectado",
        description=(
            "insertAdjacentHTML() parsea HTML e inserta en el DOM. "
            "Si el segundo argumento incluye datos del usuario, es XSS."
        ),
        recommendation="Sanitiza el HTML con DOMPurify antes de insertar.",
    ),
    _Pattern(
        name="jquery_html",
        regex=r'\$\([^)]*\)\s*\.\s*html\s*\(',
        severity=Severity.MEDIUM,
        title="jQuery .html() con posible input dinámico",
        description=(
            "jQuery .html(val) es equivalente a innerHTML. "
            "Si val contiene datos del usuario, permite XSS."
        ),
        recommendation="Usa .text() para texto plano, o sanitiza con DOMPurify.",
    ),
    _Pattern(
        name="jquery_append_dynamic",
        regex=r'\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\(',
        severity=Severity.LOW,
        title="jQuery DOM insertion detectada",
        description=(
            "Los métodos jQuery .append()/.prepend()/.after()/.before() "
            "parsean HTML si reciben un string. Si el argumento incluye "
            "datos del usuario, puede haber XSS."
        ),
        recommendation="Usa $.text() o pasa nodos DOM en lugar de strings HTML.",
    ),
]


# ── DOM XSS source-to-sink patterns ─────────────────────────
# Estos detectan cuando una fuente controlable por el usuario
# aparece cerca de un sink peligroso (misma línea o contexto).

DOM_XSS_SOURCES = [
    r'document\.URL',
    r'document\.documentURI',
    r'document\.referrer',
    r'document\.cookie',
    r'location\.hash',
    r'location\.search',
    r'location\.href',
    r'window\.name',
    r'location\.pathname',
]

DOM_XSS_SINK_KEYWORDS = [
    'innerHTML', 'outerHTML', 'document.write', 'eval',
    'insertAdjacentHTML', '.html(', 'Function(',
]

POSTMESSAGE_PATTERN = re.compile(
    r'addEventListener\s*\(\s*["\']message["\']',
    re.IGNORECASE,
)
ORIGIN_CHECK_PATTERN = re.compile(
    r'(?:event|e|evt)\.origin\s*[!=]==?',
    re.IGNORECASE,
)


class JSAnalysisScanner(BaseScanner):
    name = "js_analysis"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base_url += f":{target.port}"

        # Collect JS.
        collector = JSCollector(context.body_text, base_url)
        sources = collector.collect_all(fetch_external=True)

        all_findings: list[dict] = []

        # Run checks on each source.
        for source in sources:
            all_findings.extend(self._check_dangerous_functions(source))
            all_findings.extend(self._check_dom_xss_sinks(source))

        # Source-to-sink analysis (combined content).
        combined = collector.combined_content(sources)
        source_sink = self._check_source_to_sink(combined)
        postmessage = self._check_postmessage(combined)

        result.raw = {
            "collection": collector.stats_dict(),
            "dangerous_functions": len([
                f for f in all_findings if f["type"] == "dangerous_function"
            ]),
            "dom_xss_sinks": len([
                f for f in all_findings if f["type"] == "dom_xss_sink"
            ]),
            "source_to_sink_flows": len(source_sink),
            "postmessage_issues": len(postmessage),
        }

        # Emit findings.
        for f in all_findings:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=f["severity"],
                title=f["title"],
                description=f["description"],
                evidence=f["evidence"],
                recommendation=f["recommendation"],
            ))

        for f in source_sink:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.HIGH,
                title=f["title"],
                description=f["description"],
                evidence=f["evidence"],
                recommendation=(
                    "Nunca pases datos de fuentes controlables por el usuario "
                    "(URL, hash, referrer, cookies) directamente a sinks DOM. "
                    "Sanitiza con DOMPurify o usa textContent."
                ),
            ))

        for f in postmessage:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=f["severity"],
                title=f["title"],
                description=f["description"],
                evidence=f["evidence"],
                recommendation=(
                    "Siempre valida event.origin en message handlers: "
                    "if (event.origin !== 'https://trusted.com') return;"
                ),
            ))

        if not all_findings and not source_sink and not postmessage:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.INFO,
                title="No se detectaron patrones JS peligrosos",
                description=(
                    f"Se analizaron {collector.stats.inline_count} scripts "
                    f"inline y {collector.stats.external_fetched} externos. "
                    "No se encontraron funciones peligrosas ni sinks DOM XSS "
                    "en los patrones analizados."
                ),
            ))

        return result

    def _check_dangerous_functions(self, source: JSSource) -> list[dict]:
        """Busca funciones peligrosas en una fuente JS."""
        findings = []
        for pattern in DANGEROUS_FUNCTIONS:
            matches = list(re.finditer(pattern.regex, source.content, pattern.flags))
            if not matches:
                continue

            # Extract context for each match (surrounding lines).
            snippets = []
            for m in matches[:5]:  # Limit snippets.
                start = max(0, m.start() - 60)
                end = min(len(source.content), m.end() + 60)
                snippet = source.content[start:end].strip()
                snippets.append(snippet[:200])

            loc = source.url if source.source_type == "external" else "inline script"

            findings.append({
                "type": "dangerous_function",
                "severity": pattern.severity,
                "title": f"{pattern.title} [{loc}]",
                "description": pattern.description,
                "evidence": {
                    "source": loc,
                    "occurrences": len(matches),
                    "snippets": snippets,
                },
                "recommendation": pattern.recommendation,
            })

        return findings

    def _check_dom_xss_sinks(self, source: JSSource) -> list[dict]:
        """Busca DOM XSS sinks en una fuente JS."""
        findings = []
        for pattern in DOM_XSS_SINKS:
            matches = list(re.finditer(pattern.regex, source.content, pattern.flags))
            if not matches:
                continue

            snippets = []
            for m in matches[:5]:
                start = max(0, m.start() - 60)
                end = min(len(source.content), m.end() + 60)
                snippets.append(source.content[start:end].strip()[:200])

            loc = source.url if source.source_type == "external" else "inline script"

            findings.append({
                "type": "dom_xss_sink",
                "severity": pattern.severity,
                "title": f"{pattern.title} [{loc}]",
                "description": pattern.description,
                "evidence": {
                    "source": loc,
                    "occurrences": len(matches),
                    "snippets": snippets,
                },
                "recommendation": pattern.recommendation,
            })

        return findings

    def _check_source_to_sink(self, js_content: str) -> list[dict]:
        """
        Detecta flujos source→sink potenciales.

        Busca líneas donde una fuente DOM controlable por el usuario
        aparece en el mismo contexto que un sink peligroso.
        Esto es una heurística — no reemplaza taint analysis real,
        pero detecta los patrones más comunes y explotables.
        """
        findings = []
        lines = js_content.split('\n')

        for i, line in enumerate(lines):
            for source_pattern in DOM_XSS_SOURCES:
                if not re.search(source_pattern, line, re.IGNORECASE):
                    continue

                # Check if a sink keyword is in the same line or adjacent.
                context_window = "\n".join(
                    lines[max(0, i - 2):min(len(lines), i + 3)]
                )
                for sink in DOM_XSS_SINK_KEYWORDS:
                    if sink.lower() in context_window.lower():
                        source_name = re.search(
                            source_pattern, line, re.IGNORECASE,
                        ).group(0)
                        findings.append({
                            "title": f"Posible flujo DOM XSS: {source_name} → {sink}",
                            "description": (
                                f"Se detectó '{source_name}' (fuente controlable "
                                f"por el usuario) cerca de '{sink}' (sink DOM). "
                                "Si el dato fluye sin sanitizar, esto es DOM XSS "
                                "explotable."
                            ),
                            "evidence": {
                                "source": source_name,
                                "sink": sink,
                                "context": context_window.strip()[:300],
                                "line": i + 1,
                            },
                        })
                        break  # One finding per source per line.

        # Deduplicate by source+sink combo.
        seen = set()
        unique = []
        for f in findings:
            key = (f["evidence"]["source"], f["evidence"]["sink"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique[:10]

    def _check_postmessage(self, js_content: str) -> list[dict]:
        """Detecta handlers de postMessage sin validación de origin."""
        findings = []
        matches = list(POSTMESSAGE_PATTERN.finditer(js_content))

        for m in matches:
            # Check surrounding context for origin validation.
            start = max(0, m.start() - 50)
            end = min(len(js_content), m.end() + 500)
            context = js_content[start:end]

            has_origin_check = bool(ORIGIN_CHECK_PATTERN.search(context))

            if not has_origin_check:
                findings.append({
                    "severity": Severity.HIGH,
                    "title": "postMessage handler sin validación de origin",
                    "description": (
                        "Se detectó addEventListener('message', ...) sin "
                        "verificación de event.origin. Cualquier página "
                        "puede enviar mensajes a esta ventana, lo que "
                        "permite ataques cross-origin."
                    ),
                    "evidence": {
                        "snippet": context.strip()[:300],
                        "origin_check_found": False,
                    },
                })
            else:
                findings.append({
                    "severity": Severity.INFO,
                    "title": "postMessage handler con validación de origin",
                    "description": (
                        "Se detectó un handler de postMessage que parece "
                        "validar event.origin. Verificar que la comparación "
                        "sea estricta y contra un dominio específico."
                    ),
                    "evidence": {
                        "snippet": context.strip()[:300],
                        "origin_check_found": True,
                    },
                })

        return findings[:5]
