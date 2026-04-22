"""
Nuclei Scanner — integración con ProjectDiscovery Nuclei.

Ejecuta el binario `nuclei` contra el objetivo y parsea el output JSON.
Los resultados se mapean a Finding objects del sistema.

Diseño:
- Solo usa templates de severidad CRITICAL, HIGH y MEDIUM por defecto.
- Excluye templates que requieren interactsh (callbacks externos) para
  no filtrar IPs del servidor al exterior.
- Timeout estricto: 120s hard kill vía subprocess.
- Si nuclei no está instalado, retorna vacío sin romper la auditoría.
- Templates se descargan automáticamente en primer uso.

Categorías mapeadas:
  nuclei info → RECON
  nuclei network → PORTS
  nuclei http/panel → MISCONFIG o VULNS
  nuclei cve/* → VULNS
  nuclei exposed-panels → MISCONFIG
  nuclei default-logins → AUTH_FAILURES (mapeado a VULNS)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

# Severidades que se ejecutan por defecto.
DEFAULT_SEVERITIES = ["critical", "high", "medium"]

# Excluir estos tags para no hacer callbacks externos ni brute-force agresivo.
EXCLUDE_TAGS = "intrusive,dos,fuzz,brute"

# Tiempo máximo para el escaneo completo de nuclei.
NUCLEI_TIMEOUT_S = 120

# Mapa de severidad nuclei → AttackFlow Severity
SEVERITY_MAP: dict[str, str] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.INFO,
}

# Mapa de tipo de template → Category del finding
TEMPLATE_TYPE_MAP: dict[str, str] = {
    "http":     Category.VULNS,
    "network":  Category.PORTS,
    "ssl":      Category.TRANSPORT,
    "dns":      Category.DNS,
    "file":     Category.RECON,
    "headless": Category.VULNS,
    "code":     Category.VULNS,
    "tcp":      Category.PORTS,
    "websocket":Category.VULNS,
    "whois":    Category.RECON,
    "javascript":Category.VULNS,
}

# Tags especiales que sobreescriben la categoría
TAG_CATEGORY_MAP: dict[str, str] = {
    "panel":          Category.MISCONFIG,
    "exposed-panels": Category.MISCONFIG,
    "config":         Category.MISCONFIG,
    "misconfig":      Category.MISCONFIG,
    "default-login":  Category.VULNS,
    "auth-bypass":    Category.VULNS,
    "sqli":           Category.VULNS,
    "xss":            Category.VULNS,
    "ssrf":           Category.VULNS,
    "lfi":            Category.VULNS,
    "rce":            Category.VULNS,
    "cve":            Category.VULNS,
    "cors":           Category.HEADERS,
    "headers":        Category.HEADERS,
    "cookies":        Category.COOKIES,
    "info":           Category.RECON,
    "disclosure":     Category.RECON,
}


def _nuclei_available() -> bool:
    """True si el binario nuclei está en PATH."""
    return shutil.which("nuclei") is not None


def _get_category(template_type: str, tags: list[str]) -> str:
    """Determina la categoría del finding a partir del tipo y tags del template."""
    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in TAG_CATEGORY_MAP:
            return TAG_CATEGORY_MAP[tag_lower]
    return TEMPLATE_TYPE_MAP.get(template_type, Category.VULNS)


def _parse_nuclei_output(output_file: str) -> list[dict]:
    """Parsea el archivo JSON de output de nuclei."""
    results = []
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return results


def run_nuclei(
    target_url: str,
    severities: list[str] | None = None,
    timeout: int = NUCLEI_TIMEOUT_S,
) -> list[dict]:
    """
    Ejecuta nuclei contra target_url y retorna lista de resultados raw.
    Retorna lista vacía si nuclei no está disponible o falla.
    """
    if not _nuclei_available():
        logger.info("Nuclei no está instalado — scanner omitido.")
        return []

    if severities is None:
        severities = DEFAULT_SEVERITIES

    # Archivo temporal para la salida JSON
    run_id = uuid.uuid4().hex[:8]
    output_file = f"/tmp/nuclei_out_{run_id}.json"

    # Templates path (configurable via env)
    templates_path = os.environ.get("NUCLEI_TEMPLATES_PATH", "")

    cmd = [
        "nuclei",
        "-u", target_url,
        "-severity", ",".join(severities),
        "-exclude-tags", EXCLUDE_TAGS,
        "-no-interactsh",          # sin callbacks externos (privacidad)
        "-json-export", output_file,
        "-silent",                 # solo output JSON, sin banner
        "-timeout", "10",          # timeout por request en segundos
        "-rate-limit", "50",       # max 50 req/s — respetuoso
        "-retries", "1",
        "-stats",                  # mostrar stats en stderr (va al log del worker)
    ]

    if templates_path:
        cmd += ["-t", templates_path]

    try:
        logger.info("Nuclei: iniciando scan → %s", target_url)
        proc = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
        if proc.returncode not in (0, 1):  # 0=ok, 1=no findings, otros=error
            logger.warning("Nuclei terminó con código %s: %s", proc.returncode, proc.stderr[:500])

        results = _parse_nuclei_output(output_file)
        logger.info("Nuclei: %d resultado(s) encontrados para %s", len(results), target_url)
        return results

    except subprocess.TimeoutExpired:
        logger.warning("Nuclei timeout (%ds) para %s", timeout, target_url)
        return _parse_nuclei_output(output_file)  # Devolver lo que haya hasta ahora

    except Exception as exc:
        logger.exception("Nuclei error para %s: %s", target_url, exc)
        return []

    finally:
        # Limpiar archivo temporal
        try:
            os.unlink(output_file)
        except FileNotFoundError:
            pass


class NucleiScanner(BaseScanner):
    """
    Scanner que integra Nuclei para detección de vulnerabilidades reales.

    Ejecuta templates de severidad CRITICAL/HIGH/MEDIUM contra el objetivo.
    Genera un Finding por cada resultado de nuclei, con evidence detallada.
    """

    name = "nuclei"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not _nuclei_available():
            result.raw = {"status": "nuclei_not_installed"}
            return result

        raw_results = run_nuclei(context.target.url)
        result.raw = {
            "results_count": len(raw_results),
            "target": context.target.url,
        }

        seen_templates: set[str] = set()  # deduplicar por template ID

        for r in raw_results:
            template_id  = r.get("template-id", "")
            template_name= r.get("info", {}).get("name", template_id)
            severity_raw = r.get("info", {}).get("severity", "info").lower()
            description  = r.get("info", {}).get("description", "")
            remediation  = r.get("info", {}).get("remediation", "")
            reference    = r.get("info", {}).get("reference", [])
            tags_raw     = r.get("info", {}).get("tags", "")
            tags         = [t.strip() for t in tags_raw.split(",")] if tags_raw else []
            template_type= r.get("type", "http")
            matched_at   = r.get("matched-at", context.target.url)
            curl_command = r.get("curl-command", "")
            matcher_name = r.get("matcher-name", "")
            extracted    = r.get("extracted-results", [])

            # Deduplicar — mismo template en la misma URL
            dedup_key = f"{template_id}:{matched_at}"
            if dedup_key in seen_templates:
                continue
            seen_templates.add(dedup_key)

            severity = SEVERITY_MAP.get(severity_raw, Severity.INFO)
            category = _get_category(template_type, tags)

            # Construir evidence completa
            evidence: dict = {
                "template_id":    template_id,
                "matched_at":     matched_at,
                "severity":       severity_raw,
                "tags":           tags,
                "type":           template_type,
            }
            if matcher_name:
                evidence["matcher"] = matcher_name
            if extracted:
                evidence["extracted"] = extracted[:10]  # max 10 valores
            if curl_command:
                evidence["curl"] = curl_command[:500]

            # Reference URLs
            ref_url = ""
            if isinstance(reference, list) and reference:
                ref_url = reference[0]
            elif isinstance(reference, str):
                ref_url = reference

            # Título legible
            title = template_name
            if matcher_name and matcher_name.lower() not in template_name.lower():
                title = f"{template_name} — {matcher_name}"

            result.findings.append(
                self.finding(
                    category=category,
                    severity=severity,
                    title=f"[Nuclei] {title}",
                    description=description or f"Template {template_id} encontró una coincidencia en {matched_at}.",
                    evidence=evidence,
                    recommendation=remediation or (
                        "Revisa la documentación del template para remediation steps. "
                        "Consulta el CVE o advisory vinculado si aplica."
                    ),
                    reference_url=ref_url,
                )
            )

        return result
