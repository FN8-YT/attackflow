"""
Tasks de Celery para auditorías.

Patrón:
- La vista crea el Audit con estado PENDING y llama a
  `run_audit_task.delay(audit_id)`.
- El worker recoge la tarea, ejecuta `run_audit()` (el mismo servicio
  que antes corría síncrono), y actualiza la BD.
- La vista de polling lee el estado de la BD y redirige al informe
  cuando el status es COMPLETED o FAILED.

¿Por qué `acks_late=True` (ya configurado en base settings)?
Si el worker muere a mitad de una auditoría, la tarea NO se pierde:
Celery la reencola y otro worker la recoge. Sin esto, el acknowledge
ocurre al recibirla y si el worker muere, la tarea desaparece.

¿Por qué NO retries automáticos?
Una auditoría puede tardar minutos, consume ancho de banda contra el
objetivo, y disparar reintentos silenciosos sería abusivo. Si falla,
la marcamos como FAILED y dejamos que el usuario decida re-lanzar.
"""
from __future__ import annotations

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(bind=True, acks_late=True)
def run_audit_task(self, audit_id: int) -> None:
    """Ejecuta una auditoría completa en background."""
    # Imports dentro de la función para evitar circular imports al
    # arrancar Celery (el autodiscover carga este módulo muy temprano).
    from apps.audits.models import Audit, AuditStatus
    from apps.audits.services import run_audit

    try:
        audit = Audit.objects.get(pk=audit_id)
    except Audit.DoesNotExist:
        logger.warning("Audit %s no existe, tarea descartada.", audit_id)
        return

    # Si ya está completada o fallida (ej: duplicado por requeue), no repetir.
    if audit.status in (AuditStatus.COMPLETED, AuditStatus.FAILED):
        logger.info("Audit %s ya está %s, no se re-ejecuta.", audit_id, audit.status)
        return

    try:
        run_audit(audit)
    except Exception as exc:
        logger.exception("Audit %s crasheó inesperadamente.", audit_id)
        # Marcamos como FAILED solo si run_audit no lo hizo ya.
        audit.refresh_from_db()
        if audit.status not in (AuditStatus.COMPLETED, AuditStatus.FAILED):
            audit.status = AuditStatus.FAILED
            audit.error_message = f"Error inesperado en el worker: {exc}"
            audit.finished_at = timezone.now()
            audit.save(
                update_fields=["status", "error_message", "finished_at", "updated_at"]
            )
