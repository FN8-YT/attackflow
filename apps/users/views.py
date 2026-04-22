"""
Vistas de usuarios.

Flujo de registro:
  1. RegisterView — crea el usuario, lo loguea automáticamente y redirige al dashboard.

No hay verificación de email: acceso inmediato tras registro.
"""
from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views.generic import CreateView

from apps.audits.models import Audit, AuditStatus

from .forms import RegistrationForm
from .models import User

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------

class RegisterView(CreateView):
    """
    Registro público de nuevos usuarios.

    Crea el usuario y lo loguea directamente — sin verificación de email.
    El usuario aterriza en el dashboard de forma inmediata.
    """

    model = User
    form_class = RegistrationForm
    template_name = "users/register.html"
    success_url = reverse_lazy("users:dashboard")

    def form_valid(self, form: RegistrationForm) -> HttpResponse:
        response = super().form_valid(form)  # crea y guarda el usuario
        login(
            self.request,
            self.object,
            backend="django.contrib.auth.backends.ModelBackend",
        )
        messages.success(self.request, "¡Bienvenido a AttackFlow!")
        logger.info("New user registered: %s", self.object.email)
        return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    """Panel privado del usuario con estadísticas y auditorías recientes."""
    audits_qs = Audit.objects.filter(user=request.user)
    completed_qs = audits_qs.filter(status=AuditStatus.COMPLETED)

    stats = completed_qs.aggregate(
        avg_score=Avg("score"),
        total_completed=Count("id"),
    )

    context = {
        "audits": audits_qs.order_by("-created_at")[:20],
        "total_audits": audits_qs.count(),
        "total_completed": stats["total_completed"] or 0,
        "avg_score": round(stats["avg_score"] or 0),
    }
    return render(request, "users/dashboard.html", context)
