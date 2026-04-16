"""
Vistas de auditorías.

Fase 4: la ejecución es asíncrona. La vista crea el Audit, despacha
la task de Celery, y redirige a una página de estado que hace polling.
Cuando el worker termina, el polling detecta el cambio y redirige
al informe.

Tres preocupaciones transversales:
1. Rate limiting por usuario con django-ratelimit.
2. Cuota mensual (depende del plan).
3. Ownership: un usuario nunca puede ver auditorías de otro.

Modo degradado (Render free tier, sin worker):
- Si `CELERY_TASK_ALWAYS_EAGER=True`, la task normalmente se ejecutaría
  síncrona en el mismo proceso que hace el POST. Eso bloquea el request
  HTTP minutos y gunicorn lo mata por timeout (500).
- En su lugar lanzamos la task en un thread daemon y devolvemos el
  redirect a /status/ inmediatamente. El polling del status page
  detecta la finalización igual que lo haría con un worker real.
"""
from __future__ import annotations

import logging
import threading

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import close_old_connections
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django_ratelimit.decorators import ratelimit

from apps.reports.scoring import score_breakdown, severity_band

from .forms import AuditForm
from .models import Audit, AuditStatus
from .scanners import get_all_scanner_meta, get_available_scanners
from .tasks import run_audit_task

logger = logging.getLogger(__name__)


def _dispatch_audit(audit_id: int) -> None:
    """
    Despacha la ejecución de un audit.

    - Si hay broker Celery real (no EAGER): encola la task vía `.delay()`.
    - Si estamos en EAGER (free tier sin worker): ejecuta `run_audit` en
      un thread daemon para no bloquear el request HTTP. El thread cierra
      las conexiones de DB al terminar (Django abre una por thread).
    """
    if getattr(settings, "CELERY_TASK_ALWAYS_EAGER", False):
        def _worker():
            try:
                from .models import Audit as _Audit
                from .services import run_audit
                audit_obj = _Audit.objects.get(pk=audit_id)
                run_audit(audit_obj)
            except Exception:
                logger.exception("Thread audit %s crashed", audit_id)
            finally:
                # Cada thread en Django tiene su propia conexión a DB.
                # Si no la cerramos, el pool se queda con conexiones zombis.
                close_old_connections()

        t = threading.Thread(
            target=_worker,
            name=f"audit-{audit_id}",
            daemon=True,
        )
        t.start()
    else:
        run_audit_task.delay(audit_id)


@login_required
@ratelimit(key="user", rate="10/h", method="POST", block=True)
def create_audit(request: HttpRequest) -> HttpResponse:
    """Crea una auditoría y la despacha al worker Celery."""
    try:
        month_start = timezone.now().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        monthly_count = Audit.objects.filter(
            user=request.user, created_at__gte=month_start
        ).count()
        remaining = request.user.monthly_audit_quota - monthly_count

        if request.method == "POST":
            if remaining <= 0:
                messages.error(
                    request,
                    "Has alcanzado tu cuota mensual. Actualiza tu plan o espera al próximo mes.",
                )
                return redirect("users:dashboard")

            form = AuditForm(request.POST, user=request.user)
            if form.is_valid():
                audit = form.save(commit=False)
                audit.user = request.user
                audit.status = AuditStatus.PENDING
                audit.save()

                # Despacho: a broker Celery si existe, o a thread daemon
                # en free tier (ver `_dispatch_audit`).
                try:
                    _dispatch_audit(audit.pk)
                    messages.info(
                        request,
                        "Auditoría en cola. Los resultados aparecerán en breve.",
                    )
                except Exception as dispatch_exc:
                    logger.exception("Error despachando audit %s", audit.pk)
                    audit.status = AuditStatus.FAILED
                    audit.error_message = (
                        f"No se pudo despachar la auditoría: {dispatch_exc}"
                    )
                    audit.finished_at = timezone.now()
                    audit.save()
                    messages.error(
                        request,
                        "Error al lanzar la auditoría. Revisa los logs.",
                    )
                    return redirect("users:dashboard")

                return redirect("audits:status", pk=audit.pk)
        else:
            form = AuditForm(user=request.user)

        # Metadata de scanners para el template (checkboxes + locks).
        has_advanced = request.user.has_feature("advanced_scanners")
        all_scanners = get_all_scanner_meta()
        available_keys = {
            m.key for m in get_available_scanners("active", has_advanced)
        }

        scanner_data = []
        for meta in all_scanners:
            scanner_data.append({
                "key": meta.key,
                "label": meta.label,
                "description": meta.description,
                "tier": meta.tier,
                "default": meta.default,
                "icon": meta.icon,
                "available": meta.key in available_keys,
            })

        return render(
            request,
            "audits/new.html",
            {
                "form": form,
                "remaining": remaining,
                "has_advanced": has_advanced,
                "scanner_data": scanner_data,
            },
        )
    except Exception as e:
        logger.exception("create_audit error: %s", e)
        # Solo admins ven el traceback. Esto es TEMPORAL: mientras
        # debuggeamos el 500 en producción (sin acceso directo a logs
        # de Render), devolvemos el traceback como text/plain al staff.
        if request.user.is_authenticated and request.user.is_staff:
            import traceback as _tb
            return HttpResponse(
                "=== create_audit crashed ===\n"
                f"Exception: {type(e).__name__}: {e}\n\n"
                + _tb.format_exc(),
                content_type="text/plain; charset=utf-8",
                status=500,
            )
        raise


@login_required
def audit_status(request: HttpRequest, pk: int) -> HttpResponse:
    """
    Página de espera. Si la auditoría ya terminó, redirige al informe.
    Si no, muestra un spinner con polling JS cada 3 segundos.
    """
    audit = get_object_or_404(Audit, pk=pk, user=request.user)

    if audit.status in (AuditStatus.COMPLETED, AuditStatus.FAILED):
        return redirect("audits:detail", pk=audit.pk)

    return render(request, "audits/status.html", {"audit": audit})


@login_required
def audit_status_api(request: HttpRequest, pk: int) -> HttpResponse:
    """
    Endpoint JSON para polling. Devuelve el estado actual de la auditoría.
    El JS del template /status/ consulta esto periódicamente.

    Respuesta: {"id": 1, "status": "running", "score": null}
    """
    audit = get_object_or_404(Audit, pk=pk, user=request.user)
    return JsonResponse(
        {
            "id": audit.pk,
            "status": audit.status,
            "score": audit.score,
        }
    )


@login_required
def audit_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Informe completo de una auditoría. Solo el dueño puede verlo."""
    audit = get_object_or_404(Audit, pk=pk, user=request.user)

    # Si todavía está en proceso, redirige a la página de espera.
    if audit.status in (AuditStatus.PENDING, AuditStatus.RUNNING):
        return redirect("audits:status", pk=audit.pk)

    findings = list(audit.findings.all())
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 99))

    context = {
        "audit": audit,
        "findings": findings,
        "breakdown": score_breakdown(findings),
        "score_band": severity_band(audit.score or 0),
        "can_export_pdf": request.user.has_feature("pdf_export"),
    }
    return render(request, "audits/detail.html", context)


@login_required
def audit_list(request: HttpRequest) -> HttpResponse:
    """Listado de auditorías del usuario (redirect al dashboard por ahora)."""
    return redirect(reverse("users:dashboard"))
