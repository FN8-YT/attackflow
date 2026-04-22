"""
Celery tasks para Continuous Monitoring.

run_due_monitoring_checks:
  - Periódica (cada 5s via beat).
  - Itera MonitorTargets activos y despacha sub-tareas para los que son "due".
  - Diseño fan-out: no bloquea el beat.

run_single_monitoring_check:
  - Tarea individual por target.
  - Llama a services.run_check() y hace broadcast WebSocket del resultado.
  - acks_late=True: si el worker muere, la tarea se reencola.

_broadcast_check_result:
  - Helper para publicar en el channel layer de Channels.
  - Seguro: si channels no está configurado, el error es silencioso.
"""
from __future__ import annotations

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


# ── Helpers de broadcast ────────────────────────────────────────────────────

def _broadcast_check_result(target, check) -> None:
    """
    Publica el resultado del check en los grupos de channels:
      - monitor_{target_pk}  → página de detalle
      - dashboard_{user_pk}  → dashboard del usuario
    """
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer

        channel_layer = get_channel_layer()
        if not channel_layer:
            return  # Channels no configurado (tests sin Redis)

        payload = {
            "event":            "check_complete",
            "check_id":         check.pk,
            "target_id":        target.pk,
            "status":           check.status,
            "response_time_ms": check.response_time_ms,
            "http_status_code": check.http_status_code,
            "ssl_expiry_days":  check.ssl_expiry_days,
            "security_score":   check.security_score,
            "technologies":     check.technologies or [],
            "waf_detected":     check.waf_detected or "",
            "error_message":    check.error_message or "",
            "created_at":       check.created_at.isoformat(),
            "created_at_fmt":   check.created_at.strftime("%H:%M:%S"),
            "uptime_pct":       float(target.uptime_pct) if target.uptime_pct else None,
            "consecutive_failures": target.consecutive_failures,
            "last_ssl_days":    target.last_ssl_days,
        }

        send = async_to_sync(channel_layer.group_send)

        # Detail page
        send(f"monitor_{target.pk}", {"type": "check_update", "data": payload})

        # Dashboard (datos mínimos — solo lo que el dashboard necesita)
        send(
            f"dashboard_{target.user_id}",
            {
                "type": "check_update",
                "data": {
                    "event":        "check_complete",
                    "target_id":    target.pk,
                    "status":       check.status,
                    "response_ms":  check.response_time_ms,
                    "score":        check.security_score,
                    "waf":          check.waf_detected or "",
                },
            },
        )

    except Exception:
        logger.warning(
            "Broadcast WebSocket falló para target %s (check %s). "
            "¿Está channels-redis corriendo?",
            target.pk, check.pk,
        )


def _broadcast_surface_update(target, subdomains: list, sensitive_paths: list) -> None:
    """Broadcast del deep check (subdomains + paths) a la página de detalle."""
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer

        channel_layer = get_channel_layer()
        if not channel_layer:
            return

        payload = {
            "event":           "surface_update",
            "subdomains":      subdomains,
            "sensitive_paths": sensitive_paths,
            "active_count":    sum(1 for s in subdomains if s.get("is_active")),
            "subdomain_count": len(subdomains),
            "paths_count":     len(sensitive_paths),
        }

        async_to_sync(channel_layer.group_send)(
            f"monitor_{target.pk}",
            {"type": "surface_update", "data": payload},
        )

    except Exception:
        logger.warning("Surface broadcast falló para target %s", target.pk)


def _broadcast_screenshot(target, screenshot) -> None:
    """Notifica al browser que hay un nuevo screenshot disponible."""
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer

        channel_layer = get_channel_layer()
        if not channel_layer:
            return

        async_to_sync(channel_layer.group_send)(
            f"monitor_{target.pk}",
            {
                "type": "screenshot_update",
                "data": {
                    "event":               "screenshot_taken",
                    "screenshot_id":       screenshot.pk,
                    "diff_pct":            screenshot.diff_pct,
                    "is_defacement_alert": screenshot.is_defacement_alert,
                    "created_at":          screenshot.created_at.isoformat(),
                },
            },
        )

    except Exception:
        logger.warning("Screenshot broadcast falló para target %s", target.pk)


# ── Celery tasks ─────────────────────────────────────────────────────────────

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
    Ejecuta el check de monitorización para un target específico
    y hace broadcast del resultado via WebSocket.
    """
    from apps.monitoring.models import MonitorTarget
    from apps.monitoring.services import run_check

    try:
        target = MonitorTarget.objects.select_related("user").get(
            pk=target_id, is_active=True,
        )
    except MonitorTarget.DoesNotExist:
        logger.warning("MonitorTarget %s no existe o está inactivo.", target_id)
        return

    try:
        check = run_check(target)
        logger.info(
            "Monitor check OK: target=%s status=%s ms=%s score=%s",
            target.name, check.status, check.response_time_ms, check.security_score,
        )
        # ── Broadcast WebSocket ──────────────────────────────────────────
        _broadcast_check_result(target, check)

    except Exception as exc:
        logger.exception("Monitor check falló para target %s.", target_id)
        try:
            self.retry(countdown=60, exc=exc)
        except self.MaxRetriesExceededError:
            logger.error("Max retries para target %s. Se abandona.", target_id)
