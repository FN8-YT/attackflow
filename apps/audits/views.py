"""
Vistas de auditorías.

La ejecución es asíncrona: la vista crea el Audit, encola la task
en Celery vía `.delay()`, y redirige a la página de estado.
El worker procesa el scan en background. El polling JS en /status/
detecta el cambio de estado y redirige al informe.

Preocupaciones transversales:
1. Rate limiting por usuario con django-ratelimit.
2. Ownership: un usuario nunca puede ver auditorías de otro.
"""
from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django_ratelimit.core import is_ratelimited

from apps.reports.scoring import score_breakdown, severity_band

from .forms import AuditForm
from .models import Audit, AuditStatus
from .scanners import get_all_scanner_meta, get_available_scanners
from .tasks import run_audit_task

logger = logging.getLogger(__name__)


@login_required
def create_audit(request: HttpRequest) -> HttpResponse:
    """Crea una auditoría y la encola en Celery."""
    # Rate limiting manual para poder degradar con gracia si el cache cae.
    if request.method == "POST":
        try:
            limited = is_ratelimited(
                request=request,
                group="audits.create",
                key="user",
                rate="10/h",
                method="POST",
                increment=True,
            )
            if limited:
                messages.error(
                    request,
                    "Demasiadas auditorías en la última hora. Inténtalo más tarde.",
                )
                return redirect("users:dashboard")
        except Exception as rl_exc:
            # Cache caído: no bloqueamos al usuario, seguimos.
            logger.warning("Rate limit check failed (cache down?): %s", rl_exc)

    if request.method == "POST":
        form = AuditForm(request.POST, user=request.user)
        if form.is_valid():
            audit = form.save(commit=False)
            audit.user = request.user
            audit.status = AuditStatus.PENDING
            audit.save()

            try:
                run_audit_task.delay(audit.pk)
                messages.info(
                    request,
                    "Auditoría en cola. Los resultados aparecerán en breve.",
                )
            except Exception as dispatch_exc:
                logger.exception("Error encolando audit %s", audit.pk)
                audit.status = AuditStatus.FAILED
                audit.error_message = f"No se pudo encolar la auditoría: {dispatch_exc}"
                audit.finished_at = timezone.now()
                audit.save()
                messages.error(request, "Error al lanzar la auditoría. Revisa los logs.")
                return redirect("users:dashboard")

            return redirect("audits:status", pk=audit.pk)
    else:
        form = AuditForm(user=request.user)

    # Metadata de scanners para el template.
    # active_only=True indica que el scanner requiere modo activo.
    all_scanners = get_all_scanner_meta()
    scanner_data = [
        {
            "key": meta.key,
            "label": meta.label,
            "description": meta.description,
            "tier": meta.tier,
            "default": meta.default,
            "icon": meta.icon,
            "active_only": meta.tier == "active",
        }
        for meta in all_scanners
    ]

    return render(
        request,
        "audits/new.html",
        {
            "form": form,
            "scanner_data": scanner_data,
        },
    )


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
    Endpoint JSON para polling del estado de una auditoría.
    El JS del template /status/ consulta esto periódicamente.

    Respuesta: {"id": 1, "status": "running", "score": null}
    """
    audit = get_object_or_404(Audit, pk=pk, user=request.user)
    return JsonResponse({
        "id": audit.pk,
        "status": audit.status,
        "score": audit.score,
    })


@login_required
def audit_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Informe completo de una auditoría. Solo el dueño puede verlo."""
    audit = get_object_or_404(Audit, pk=pk, user=request.user)

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
    }
    return render(request, "audits/detail.html", context)


@login_required
def audit_list(request: HttpRequest) -> HttpResponse:
    """Listado de auditorías del usuario (redirect al dashboard)."""
    return redirect(reverse("users:dashboard"))
