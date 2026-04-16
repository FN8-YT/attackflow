"""
Celery tasks para Continuous Monitoring.

run_due_monitoring_checks:
  - Tarea periódica (cada 60s via beat).
  - Itera los MonitorTarget activos y despacha sub-tareas
    para los que son "due" según su check_interval.
  - Diseño fan-out: no bloquea el beat, cada check corre en su propio worker.

run_single_monitoring_check:
  - Tarea individual por target.
  - Llama a services.run_check() y maneja errores.
  - acks_late=True: si el worker muere, la tarea se reencola.
"""
from __future__ import annotations

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(ignore_result=True)
def run_due_monitoring_checks() -> None:
    """
    Tarea periódica: despacha checks para todos los targets activos que
    sean 'due' según su intervalo configurado.
    """
    from apps.monitoring.models import MonitorTarget

    targets = MonitorTarget.objects.filter(is_active=True).select_related("user")
    dispatched = 0

    for target in targets:
        if target.is_due:
            run_single_monitoring_check.delay(target.pk)
            dispatched += 1

    if dispatched:
        logger.info("Monitoring: %d check(s) despachados.", dispatched)


@shared_task(bind=True, acks_late=True, max_retries=1)
def run_single_monitoring_check(self, target_id: int) -> None:
    """
    Ejecuta el check de monitorización para un target específico.
    """
    from apps.monitoring.models import MonitorTarget
    from apps.monitoring.services import run_check

    try:
        target = MonitorTarget.objects.get(pk=target_id, is_active=True)
    except MonitorTarget.DoesNotExist:
        logger.warning("MonitorTarget %s no existe o está inactivo.", target_id)
        return

    try:
        check = run_check(target)
        logger.info(
            "Monitor check OK: target=%s status=%s ms=%s",
            target.name, check.status, check.response_time_ms,
        )
    except Exception as exc:
        logger.exception("Monitor check falló para target %s.", target_id)
        try:
            self.retry(countdown=60, exc=exc)
        except self.MaxRetriesExceededError:
            logger.error("Max retries para target %s. Se abandona.", target_id)
