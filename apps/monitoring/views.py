"""
Vistas de Continuous Monitoring.
"""
from __future__ import annotations

import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .checks.scoring import score_grade
from .forms import MonitorTargetForm
from .models import MonitorChange, MonitorCheck, MonitorScreenshot, MonitorSubdomain, MonitorTarget


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@login_required
def monitor_dashboard(request: HttpRequest) -> HttpResponse:
    targets = (
        MonitorTarget.objects
        .filter(user=request.user)
        .order_by("-created_at")
    )

    since = timezone.now() - timezone.timedelta(hours=24)
    recent_changes = (
        MonitorChange.objects
        .filter(target__user=request.user, created_at__gte=since)
        .select_related("target", "monitor_check")
        .order_by("-created_at")[:60]
    )

    # Sparkline data (last 12 checks per target) — embedded for no extra requests
    sparklines: dict[int, list] = {}
    for target in targets:
        checks = list(
            MonitorCheck.objects
            .filter(target=target)
            .order_by("-created_at")[:12]
        )
        checks.reverse()
        sparklines[target.pk] = [
            {
                "ms":     c.response_time_ms or 0,
                "status": c.status,
            }
            for c in checks
        ]

    return render(request, "monitoring/dashboard.html", {
        "targets":        targets,
        "recent_changes": recent_changes,
        "sparklines_json": json.dumps(sparklines),
    })


# ---------------------------------------------------------------------------
# Add target
# ---------------------------------------------------------------------------

@login_required
def monitor_add(request: HttpRequest) -> HttpResponse:
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

    return render(request, "monitoring/add.html", {"form": form})


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------

@login_required
def monitor_detail(request: HttpRequest, pk: int) -> HttpResponse:
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    checks = list(
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")[:60]
    )
    changes = list(
        MonitorChange.objects
        .filter(target=target)
        .select_related("monitor_check")
        .order_by("-created_at")[:100]
    )

    # Security grade para el último check
    grade, grade_color = ("?", "var(--text-gray)")
    if target.last_security_score is not None:
        grade, grade_color = score_grade(target.last_security_score)

    # Sensitive paths del último check con score
    last_check = checks[0] if checks else None
    sensitive_paths = last_check.sensitive_paths_found if last_check else []

    # Security headers analysis del último check
    header_analysis = []
    GRADED_HEADERS = [
        ("Content-Security-Policy",        "CSP",   "critical"),
        ("Strict-Transport-Security",       "HSTS",  "high"),
        ("X-Content-Type-Options",          "XCTO",  "medium"),
        ("X-Frame-Options",                 "XFO",   "medium"),
        ("Referrer-Policy",                 "RP",    "low"),
        ("Permissions-Policy",              "PP",    "low"),
        ("Cross-Origin-Opener-Policy",      "COOP",  "low"),
        ("Cross-Origin-Resource-Policy",    "CORP",  "low"),
        ("Cross-Origin-Embedder-Policy",    "COEP",  "low"),
        ("X-XSS-Protection",                "XSP",   "info"),
        ("Access-Control-Allow-Origin",     "CORS",  "info"),
    ]
    if last_check:
        snapshot = last_check.headers_snapshot or {}
        for full_name, short, importance in GRADED_HEADERS:
            value = snapshot.get(full_name, "")
            header_analysis.append({
                "name":       full_name,
                "short":      short,
                "importance": importance,
                "present":    bool(value),
                "value":      value,
            })

    return render(request, "monitoring/detail.html", {
        "target":          target,
        "checks":          checks,
        "changes":         changes,
        "grade":           grade,
        "grade_color":     grade_color,
        "sensitive_paths": sensitive_paths,
        "header_analysis": header_analysis,
        "last_check":      last_check,
    })


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

@login_required
def monitor_delete(request: HttpRequest, pk: int) -> HttpResponse:
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
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)
    target.is_active = not target.is_active
    target.save(update_fields=["is_active", "updated_at"])
    state = "activado" if target.is_active else "pausado"

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({
            "is_active": target.is_active,
            "state":     state,
            "message":   f"Target «{target.name}» {state}.",
        })

    messages.success(request, f"Target «{target.name}» {state}.")
    referer = request.META.get("HTTP_REFERER", "")
    if referer:
        return redirect(referer)
    return redirect("monitoring:detail", pk=pk)


# ---------------------------------------------------------------------------
# Run now
# ---------------------------------------------------------------------------

@login_required
@require_POST
def monitor_run_now(request: HttpRequest, pk: int) -> HttpResponse:
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    try:
        from .services import run_check
        check = run_check(target)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({
                "ok":             True,
                "check_id":       check.pk,
                "status":         check.status,
                "response_ms":    check.response_time_ms,
                "http_code":      check.http_status_code,
                "security_score": check.security_score,
                "created_at":     check.created_at.isoformat(),
            })
        messages.success(request, f"Check completado para «{target.name}».")
    except Exception as exc:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"ok": False, "error": str(exc)}, status=500)
        messages.error(request, f"El check falló: {exc}")

    return redirect("monitoring:detail", pk=pk)


# ---------------------------------------------------------------------------
# JSON endpoints
# ---------------------------------------------------------------------------

@login_required
def monitor_status_json(request: HttpRequest, pk: int) -> JsonResponse:
    """Estado actual del target para polling ligero desde la UI."""
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    last_check = (
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")
        .first()
    )

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
        "target_id":            target.pk,
        "current_status":       target.current_status,
        "status_color":         target.status_color,
        "last_check_at":        target.last_check_at.isoformat() if target.last_check_at else None,
        "last_response_ms":     target.last_response_ms,
        "last_http_status":     target.last_http_status,
        "last_ssl_days":        target.last_ssl_days,
        "uptime_pct":           float(target.uptime_pct) if target.uptime_pct is not None else None,
        "consecutive_failures": target.consecutive_failures,
        "last_security_score":  target.last_security_score,
        "last_waf":             target.last_waf,
        "recent_changes":       recent_changes,
        "last_check": {
            "status":           last_check.status,
            "http_status_code": last_check.http_status_code,
            "response_time_ms": last_check.response_time_ms,
            "ssl_expiry_days":  last_check.ssl_expiry_days,
            "security_score":   last_check.security_score,
            "technologies":     last_check.technologies,
            "waf_detected":     last_check.waf_detected,
            "created_at":       last_check.created_at.isoformat(),
        } if last_check else None,
    })


@login_required
def monitor_history_json(request: HttpRequest, pk: int) -> JsonResponse:
    """
    Serie temporal de response times para el gráfico Chart.js.
    Retorna los últimos N checks ordenados cronológicamente.
    """
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)
    limit  = min(int(request.GET.get("n", 50)), 200)

    checks = list(
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")[:limit]
    )
    checks.reverse()

    return JsonResponse({
        "labels":          [c.created_at.strftime("%d/%m %H:%M") for c in checks],
        "response_times":  [c.response_time_ms or 0                for c in checks],
        "statuses":        [c.status                               for c in checks],
        "http_codes":      [c.http_status_code or 0                for c in checks],
        "security_scores": [c.security_score if c.security_score is not None else None
                           for c in checks],
    })


@login_required
def monitor_checks_json(request: HttpRequest, pk: int) -> JsonResponse:
    """
    Retorna checks nuevos desde since_id para polling del Check Log.

    GET /monitoring/<pk>/checks.json/?since_id=<int>
    Retorna checks con pk > since_id, en orden cronológico (más antiguos primero).
    """
    target   = get_object_or_404(MonitorTarget, pk=pk, user=request.user)
    since_id = int(request.GET.get("since_id", 0))

    qs = MonitorCheck.objects.filter(target=target)
    if since_id:
        qs = qs.filter(pk__gt=since_id)

    checks = list(qs.order_by("-created_at")[:30])

    return JsonResponse({
        "checks": [
            {
                "id":               c.pk,
                "status":           c.status,
                "http_status_code": c.http_status_code,
                "response_time_ms": c.response_time_ms,
                "ssl_expiry_days":  c.ssl_expiry_days,
                "security_score":   c.security_score,
                "technologies":     c.technologies or [],
                "waf_detected":     c.waf_detected or "",
                "error_message":    c.error_message or "",
                "created_at":       c.created_at.isoformat(),
                "created_at_fmt":   c.created_at.strftime("%H:%M:%S"),
            }
            for c in reversed(checks)  # más antiguos primero
        ],
        "latest_id": checks[0].pk if checks else since_id,
    })


@login_required
def monitor_screenshot_json(request: HttpRequest, pk: int) -> JsonResponse:
    """
    Devuelve el screenshot más reciente (base64) + diff info.
    GET /monitoring/<pk>/screenshot.json/
    """
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    latest = (
        MonitorScreenshot.objects
        .filter(monitor_check__target=target)
        .order_by("-created_at")
        .first()
    )

    if not latest:
        return JsonResponse({"has_screenshot": False})

    # Historial de diff para sparkline visual
    history = list(
        MonitorScreenshot.objects
        .filter(monitor_check__target=target)
        .order_by("-created_at")[:20]
        .values("diff_pct", "is_defacement_alert", "created_at", "image_hash")
    )
    for h in history:
        h["created_at"] = h["created_at"].isoformat()

    return JsonResponse({
        "has_screenshot":       True,
        "screenshot_id":        latest.pk,
        "image_b64":            latest.image_b64,
        "image_hash":           latest.image_hash,
        "diff_pct":             latest.diff_pct,
        "is_defacement_alert":  latest.is_defacement_alert,
        "width":                latest.width,
        "height":               latest.height,
        "created_at":           latest.created_at.isoformat(),
        "history":              history,
    })


@login_required
def monitor_surface_json(request: HttpRequest, pk: int) -> JsonResponse:
    """
    Retorna los datos de Attack Surface del target:
    subdomains activos/inactivos + sensitive paths del último check.

    GET /monitoring/<pk>/surface.json/
    """
    target = get_object_or_404(MonitorTarget, pk=pk, user=request.user)

    subdomains = list(
        MonitorSubdomain.objects
        .filter(target=target)
        .order_by("-is_active", "hostname")
        .values(
            "hostname", "subdomain", "ip_address",
            "is_active", "http_status_code", "response_time_ms", "last_seen_at",
        )
    )
    for s in subdomains:
        if s["last_seen_at"]:
            s["last_seen_at"] = s["last_seen_at"].isoformat()

    # Sensitive paths del check con paths más reciente
    last_check_with_paths = (
        MonitorCheck.objects
        .filter(target=target)
        .exclude(sensitive_paths_found=[])
        .order_by("-created_at")
        .first()
    )
    sensitive_paths = last_check_with_paths.sensitive_paths_found if last_check_with_paths else []

    return JsonResponse({
        "subdomains":        subdomains,
        "sensitive_paths":   sensitive_paths,
        "last_deep_check_at": (
            target.last_deep_check_at.isoformat()
            if target.last_deep_check_at else None
        ),
        "subdomain_count":   len(subdomains),
        "active_count":      sum(1 for s in subdomains if s["is_active"]),
    })
