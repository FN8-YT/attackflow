"""
Vistas de reportes — exportación PDF.

Usa weasyprint para renderizar el template HTML a PDF.
Solo disponible para usuarios con la feature 'pdf_export' (Premium+).
"""
from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string

from apps.audits.models import Audit, AuditStatus
from apps.reports.scoring import score_breakdown, severity_band

logger = logging.getLogger(__name__)


@login_required
def export_pdf(request: HttpRequest, pk: int) -> HttpResponse:
    """Genera y descarga el informe de auditoría como PDF."""
    audit = get_object_or_404(Audit, pk=pk, user=request.user)

    # Feature gate: solo premium+ puede exportar.
    if not request.user.has_feature("pdf_export"):
        messages.error(
            request,
            "La exportación a PDF requiere un plan Premium. "
            "Consulta la página de planes para más información.",
        )
        return redirect("audits:detail", pk=audit.pk)

    if audit.status != AuditStatus.COMPLETED:
        messages.error(request, "Solo se pueden exportar auditorías completadas.")
        return redirect("audits:detail", pk=audit.pk)

    findings = list(audit.findings.all())
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 99))

    context = {
        "audit": audit,
        "findings": findings,
        "breakdown": score_breakdown(findings),
        "score_band": severity_band(audit.score or 0),
    }

    html_string = render_to_string("reports/pdf_report.html", context)

    # Importar weasyprint aquí para evitar error de import si no está instalado.
    import weasyprint

    pdf_file = weasyprint.HTML(string=html_string).write_pdf()

    # Nombre limpio para el archivo.
    safe_host = audit.normalized_host or "audit"
    filename = f"SecurityAudit_{safe_host}_{audit.created_at:%Y%m%d}.pdf"

    response = HttpResponse(pdf_file, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
