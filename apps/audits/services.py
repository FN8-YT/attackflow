"""
Servicio orquestador de auditorías.

Responsabilidades:
- Recibe un Audit recién creado (estado PENDING).
- Valida y resuelve la URL (anti-SSRF).
- Hace la petición HTTP única y la comparte en el contexto.
- Ejecuta todos los scanners en orden.
- Persiste findings con bulk_create.
- Calcula score y marca el audit como COMPLETED/FAILED.

El orquestador no conoce la internal de los scanners — solo la interfaz
BaseScanner. Eso es la esencia del Strategy pattern aplicado al dominio.
"""
from __future__ import annotations

import logging
from dataclasses import asdict

import requests
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.audits.models import Audit, AuditStatus, Finding
from apps.audits.scanners import ScanContext, get_scanners_for_audit
from apps.audits.validators import resolve_and_validate
from apps.reports.scoring import compute_score

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 15         # segundos
HTTP_MAX_BYTES = 2 * 1024 * 1024  # 2 MB — protege contra bombas de respuesta
USER_AGENT = "SecurityAuditBot/0.1 (+https://example.com/bot)"


def run_audit(audit: Audit) -> None:
    """Ejecuta una auditoría end-to-end de forma síncrona."""
    logger.info("Running audit %s for %s", audit.pk, audit.target_url)
    audit.status = AuditStatus.RUNNING
    audit.started_at = timezone.now()
    audit.save(update_fields=["status", "started_at", "updated_at"])

    try:
        target = resolve_and_validate(audit.target_url)
    except ValidationError as exc:
        _mark_failed(audit, f"URL rechazada: {exc.messages[0]}")
        return

    audit.normalized_host = target.hostname
    audit.save(update_fields=["normalized_host", "updated_at"])

    context = ScanContext(target=target)
    _prefetch_http(context)

    # Seleccionar scanners según modo y selección del usuario.
    selected_keys = audit.selected_scanners or None
    scanners = get_scanners_for_audit(audit.scan_mode, selected_keys)

    all_findings = []
    raw_bundle: dict = {}

    for scanner in scanners:
        try:
            result = scanner.run(context)
            raw_bundle[scanner.name] = result.raw
            all_findings.extend(result.findings)
        except Exception as exc:  # nunca dejamos que un scanner tumbe el audit
            logger.exception("Scanner %s failed", scanner.name)
            raw_bundle[scanner.name] = {"error": str(exc)}

    # Persistencia atómica: findings + audit completado en la misma tx.
    try:
        with transaction.atomic():
            Finding.objects.bulk_create(
                [
                    Finding(audit=audit, **asdict(fd))
                    for fd in all_findings
                ]
            )
            audit.raw_data = raw_bundle
            audit.score = compute_score(all_findings)
            audit.status = AuditStatus.COMPLETED
            audit.finished_at = timezone.now()
            audit.save(
                update_fields=[
                    "raw_data",
                    "score",
                    "status",
                    "finished_at",
                    "updated_at",
                ]
            )
    except Exception as exc:
        logger.exception("Error persistiendo audit %s", audit.pk)
        _mark_failed(audit, f"Error interno: {exc}")
        return

    logger.info(
        "Audit %s completed in %.2fs with score %s",
        audit.pk,
        audit.duration_seconds or 0,
        audit.score,
    )


def _prefetch_http(context: ScanContext) -> None:
    """
    Hace una única request al objetivo y la deja disponible en el contexto.
    Limita el tamaño del body para evitar 'response bombs'.
    """
    target = context.target
    try:
        response = requests.get(
            target.url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            stream=True,
        )
        # Leemos a lo sumo HTTP_MAX_BYTES del body.
        content = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content.extend(chunk)
            if len(content) >= HTTP_MAX_BYTES:
                break
        response._content = bytes(content)  # type: ignore[attr-defined]
        context.http_response = response
    except requests.RequestException as exc:
        context.http_error = f"No se pudo conectar: {exc}"
        logger.warning("HTTP fetch failed for %s: %s", target.url, exc)


def _mark_failed(audit: Audit, message: str) -> None:
    audit.status = AuditStatus.FAILED
    audit.error_message = message
    audit.finished_at = timezone.now()
    audit.save(
        update_fields=["status", "error_message", "finished_at", "updated_at"]
    )
