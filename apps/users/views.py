"""
Vistas de usuarios.

Flujo de verificación de email:
  1. RegisterView          → crea usuario (is_verified=False), envía email, redirige a verify_pending.
  2. verify_email_link     → valida token de URL, marca is_verified=True, loguea, redirige a dashboard.
  3. verify_pending        → página "revisa tu correo" con botón de reenvío.
  4. resend_verification   → reenvía el email (rate-limited: 3/hora por usuario/IP).
  5. verify_invalid        → página de error para tokens expirados o inválidos.

Dos capas de protección contra usuarios no verificados:
  - EmailAuthenticationForm.confirm_login_allowed(): bloquea en el form de login.
  - EmailVerificationMiddleware: bloquea a nivel de request si ya tienen sesión.
"""
from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic import CreateView
from django_ratelimit.decorators import ratelimit

from apps.audits.models import Audit, AuditStatus

from .forms import RegistrationForm
from .models import PLAN_CONFIG, User
from .tokens import make_verification_token, verify_verification_token

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper interno
# ---------------------------------------------------------------------------

def _send_verification_email(request: HttpRequest, user: User) -> None:
    """
    Genera el token, construye el enlace absoluto y despacha el email.
    Separado como función para reutilizarlo desde RegisterView y resend.
    """
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    token = make_verification_token(user)
    verify_url = request.build_absolute_uri(
        reverse_lazy("users:verify_email", kwargs={"token": token})
    )

    subject = render_to_string(
        "email/verify_email_subject.txt",
        {"user": user},
    ).strip()  # strip() elimina el \n final que rompe los headers SMTP

    body = render_to_string(
        "email/verify_email.txt",
        {"user": user, "verify_url": verify_url, "valid_hours": 24},
    )

    send_mail(
        subject=subject,
        message=body,
        from_email=None,   # usa DEFAULT_FROM_EMAIL de settings
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info("Verification email sent to %s", user.email)


# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------

class RegisterView(CreateView):
    """
    Registro público de nuevos usuarios.

    Diferencias respecto a la versión anterior:
      - NO hace auto-login: primero hay que verificar el email.
      - Envía el email de verificación tras crear la cuenta.
      - Redirige a verify_pending en lugar del dashboard.
    """

    model = User
    form_class = RegistrationForm
    template_name = "users/register.html"
    success_url = reverse_lazy("users:verify_pending")

    def form_valid(self, form: RegistrationForm) -> HttpResponse:
        response = super().form_valid(form)  # crea el usuario; is_verified=False por defecto

        try:
            _send_verification_email(self.request, self.object)
        except Exception:
            logger.exception(
                "Failed to send verification email to %s after registration.",
                self.object.email,
            )
            messages.warning(
                self.request,
                "No pudimos enviar el email de verificación. "
                "Usa el botón 'reenviar' en la siguiente página.",
            )

        # Guardamos el email en sesión para mostrarlo en verify_pending
        # sin exponer el PK del usuario en la URL.
        self.request.session["pending_verification_email"] = self.object.email
        return response


# ---------------------------------------------------------------------------
# Verificación por enlace
# ---------------------------------------------------------------------------

def verify_email_link(request: HttpRequest, token: str) -> HttpResponse:
    """
    Procesa el enlace de verificación: GET /verify/<token>/

    Valida el token → marca is_verified=True → crea sesión → dashboard.
    Si el token es inválido o expirado → página de error con opción de reenviar.
    """
    user = verify_verification_token(token)

    if user is None:
        return render(request, "users/verify_invalid.html", status=400)

    if user.is_verified:
        # Token válido pero ya verificado: simplemente logueamos.
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        messages.info(request, "Tu cuenta ya estaba verificada.")
        return redirect("users:dashboard")

    user.is_verified = True
    user.save(update_fields=["is_verified"])

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")

    logger.info("User %s completed email verification.", user.email)
    messages.success(request, "¡Email verificado! Bienvenido a AttackFlow.")
    return redirect("users:dashboard")


# ---------------------------------------------------------------------------
# Verificación pendiente
# ---------------------------------------------------------------------------

def verify_pending(request: HttpRequest) -> HttpResponse:
    """Página 'Revisa tu correo' con botón de reenvío."""
    email = request.session.get("pending_verification_email", "")
    return render(request, "users/verify_pending.html", {"email": email})


# ---------------------------------------------------------------------------
# Reenvío
# ---------------------------------------------------------------------------

@ratelimit(key="user_or_ip", rate="3/h", method="POST", block=False)
def resend_verification(request: HttpRequest) -> HttpResponse:
    """
    POST /verify/resend/  — Reenvía el email de verificación.

    Rate-limited: 3 envíos/hora por usuario+IP para prevenir abuso.
    Siempre devuelve el mismo mensaje de éxito para evitar
    enumeración de cuentas (user enumeration).
    """
    if request.method != "POST":
        return redirect("users:verify_pending")

    if getattr(request, "limited", False):
        messages.error(
            request,
            "Demasiados intentos. Espera antes de solicitar otro enlace.",
        )
        return redirect("users:verify_pending")

    email = request.POST.get("email", "").strip().lower()
    if not email:
        messages.error(request, "Introduce tu dirección de email.")
        return redirect("users:verify_pending")

    _SAFE_MSG = (
        "Si existe una cuenta sin verificar con ese email, "
        "recibirás un nuevo enlace en breve."
    )

    try:
        user = User.objects.get(email=email, is_verified=False)
    except User.DoesNotExist:
        # Misma respuesta tanto si no existe como si ya está verificado.
        messages.success(request, _SAFE_MSG)
        return redirect("users:verify_pending")

    try:
        _send_verification_email(request, user)
        request.session["pending_verification_email"] = user.email
        messages.success(request, _SAFE_MSG)
    except Exception:
        logger.exception("Failed to resend verification email to %s.", email)
        messages.error(request, "Error al enviar el email. Inténtalo de nuevo en unos minutos.")

    return redirect("users:verify_pending")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    """Panel privado del usuario con estadísticas y auditorías recientes."""
    audits_qs = Audit.objects.filter(user=request.user)
    completed_qs = audits_qs.filter(status=AuditStatus.COMPLETED)

    month_start = timezone.now().replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    month_count = audits_qs.filter(created_at__gte=month_start).count()
    remaining = request.user.monthly_audit_quota - month_count

    stats = completed_qs.aggregate(
        avg_score=Avg("score"),
        total_completed=Count("id"),
    )

    context = {
        "audits": audits_qs.order_by("-created_at")[:20],
        "total_audits": audits_qs.count(),
        "total_completed": stats["total_completed"] or 0,
        "avg_score": round(stats["avg_score"] or 0),
        "month_count": month_count,
        "remaining": remaining,
    }
    return render(request, "users/dashboard.html", context)


# ---------------------------------------------------------------------------
# Planes
# ---------------------------------------------------------------------------

@login_required
def plans(request: HttpRequest) -> HttpResponse:
    """Página de comparación de planes."""
    return render(request, "users/plans.html", {"plans": PLAN_CONFIG})
