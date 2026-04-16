"""
Vistas de Continuous Monitoring.

MonitorDashboardView   — lista de targets del usuario + cambios recientes.
MonitorTargetCreateView — formulario de alta con plan gating.
MonitorTargetDetailView — detalle de un target: historial de checks y cambios.
MonitorTargetDeleteView — baja de un target con confirmación.
monitor_run_now         — dispara un check inmediato (POST).
monitor_status_json     — endpoint JSON con estado actual del target (polling).
"""
from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import MonitorTargetForm, get_monitor_limit
from .models import MonitorChange, MonitorCheck, MonitorTarget


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@login_required
def monitor_dashboard(request: HttpRequest) -> HttpResponse:
    """Vista principal: grid de targets + feed de cambios recientes."""
    targets = (
        MonitorTarget.objects
        .filter(user=request.user)
        .prefetch_related("checks")
        .order_by("-created_at")
    )

    # Cambios recientes (últimas 24 h, todos los targets del usuario).
    since = timezone.now() - timezone.timedelta(hours=24)
    recent_changes = (
        MonitorChange.objects
        .filter(target__user=request.user, created_at__gte=since)
        .select_related("target", "monitor_check")
        .order_by("-created_at")[:50]
    )

    limit = get_monitor_limit(request.user)
    can_add = targets.count() < limit

    return render(request, "monitoring/dashboard.html", {
        "targets": targets,
        "recent_changes": recent_changes,
        "target_limit": limit,
        "can_add": can_add,
        "used": targets.count(),
    })


# ---------------------------------------------------------------------------
# Add target
# ---------------------------------------------------------------------------

@login_required
def monitor_add(request: HttpRequest) -> HttpResponse:
    """Formulario para añadir un MonitorTarget."""
    limit = get_monitor_limit(request.user)
    current_count = MonitorTarget.objects.filter(user=request.user).count()

    if request.method == "POST":
        form = MonitorTargetForm(request.POST, user=request.user)
        if form.is_valid():
            target = form.save(commit=False)
            target.user = request.user
            target.save()
            messages.success(request, f"Target «{target.name}» añadido correctamente.")
            return redirect("monitoring:detail", pk=target.pk)
    else:
        form = MonitorTargetForm(user=request.user)

    return render(request, "monitoring/add.html", {
        "form": form,
        "target_limit": limit,
        "used": current_count,
    })


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------

@login_required
def monitor_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Detalle de un target: historial de checks y lista de cambios."""
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    # Convertimos a list() antes de pasar al template:
    # el tag "{% for x in checks reversed %}" llama a reversed() de Python,
    # que en un QuerySet sliceado ([:50]) lanza OperationalError porque Django
    # no permite .reverse() sobre querysets ya cortados. Con una lista, funciona.
    checks = list(
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")[:50]
    )
    changes = list(
        MonitorChange.objects
        .filter(target=target)
        .select_related("monitor_check")
        .order_by("-created_at")[:100]
    )

    return render(request, "monitoring/detail.html", {
        "target": target,
        "checks": checks,
        "changes": changes,
    })


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

@login_required
def monitor_delete(request: HttpRequest, pk: int) -> HttpResponse:
    """Elimina un target tras confirmación POST."""
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    if request.method == "POST":
        name = target.name
        target.delete()
        messages.success(request, f"Target «{name}» eliminado.")
        return redirect("monitoring:dashboard")

    return render(request, "monitoring/confirm_delete.html", {"target": target})


# ---------------------------------------------------------------------------
# Toggle active
# ---------------------------------------------------------------------------

@login_required
@require_POST
def monitor_toggle(request: HttpRequest, pk: int) -> HttpResponse:
    """Activa / desactiva un target."""
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)
    target.is_active = not target.is_active
    target.save(update_fields=["is_active", "updated_at"])
    state = "activado" if target.is_active else "pausado"
    messages.success(request, f"Target «{target.name}» {state}.")
    return redirect("monitoring:detail", pk=pk)


# ---------------------------------------------------------------------------
# Run now
# ---------------------------------------------------------------------------

@login_required
@require_POST
def monitor_run_now(request: HttpRequest, pk: int) -> HttpResponse:
    """Ejecuta un check inmediato y síncrono para el target.

    Se ejecuta directamente en el proceso web (sin Celery) porque:
    - El check es rápido (<10 s de timeout).
    - En el plan free de Render no hay worker disponible.
    - El usuario espera feedback inmediato.
    """
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    try:
        from apps.monitoring.services import run_check
        run_check(target)
        messages.success(request, f"Check completado para «{target.name}».")
    except Exception as exc:
        messages.error(request, f"El check falló: {exc}")

    return redirect("monitoring:detail", pk=pk)


# ---------------------------------------------------------------------------
# JSON status endpoint (para polling ligero desde la UI)
# ---------------------------------------------------------------------------

@login_required
def monitor_status_json(request: HttpRequest, pk: int) -> JsonResponse:
    """Devuelve el estado actual de un target en JSON."""
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    # Último check.
    last_check = (
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")
        .first()
    )

    # Cambios en las últimas 24 h.
    since = timezone.now() - timezone.timedelta(hours=24)
    recent_changes = list(
        MonitorChange.objects
        .filter(target=target, created_at__gte=since)
        .values("change_type", "severity", "description", "created_at")
        .order_by("-created_at")[:10]
    )
    for c in recent_changes:
        c["created_at"] = c["created_at"].isoformat()

    return JsonResponse({
        "target_id":           target.pk,
        "name":                target.name,
        "current_status":      target.current_status,
        "status_color":        target.status_color,
        "last_check_at":       target.last_check_at.isoformat() if target.last_check_at else None,
        "last_response_ms":    target.last_response_ms,
        "last_http_status":    target.last_http_status,
        "last_ssl_days":       target.last_ssl_days,
        "uptime_pct":          float(target.uptime_pct) if target.uptime_pct is not None else None,
        "consecutive_failures":target.consecutive_failures,
        "is_active":           target.is_active,
        "recent_changes":      recent_changes,
        "last_check": {
            "status":          last_check.status,
            "http_status_code":last_check.http_status_code,
            "response_time_ms":last_check.response_time_ms,
            "ssl_expiry_days": last_check.ssl_expiry_days,
            "ssl_issuer":      last_check.ssl_issuer,
            "error_message":   last_check.error_message,
            "created_at":      last_check.created_at.isoformat(),
        } if last_check else None,
    })
