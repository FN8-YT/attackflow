"""
Middleware de verificación de email.

Intercepta TODAS las requests de usuarios autenticados. Si el usuario
no ha verificado su email, lo redirige a la página de verificación
pendiente — excepto para las URLs exentas (auth, verificación, admin, static).

Por qué middleware y no solo un decorator:
  - Es un requisito transversal: aplica a TODA la plataforma.
  - Añadir @verification_required a cada vista es propenso a olvidos.
  - Centralizar aquí garantiza que ninguna vista nueva quede sin proteger.

Notas:
  - Solo actúa sobre usuarios autenticados (AnonymousUser pasa).
  - Las URLs exentas se comparan por prefijo de path para evitar
    depender de nombres de URL (más robusto ante refactors).
  - DISABLE_PLAN_LIMITS no desactiva esta comprobación: en dev
    el email va a consola y el flujo completo es testeable.
"""
from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse_lazy

# Prefijos de path que no requieren verificación.
# Se usan startswith() para cubrir sub-rutas automáticamente.
_EXEMPT_PREFIXES = (
    "/accounts/",       # login, logout, register
    "/verify/",         # el propio flujo de verificación
    "/admin/",          # panel de Django
    "/static/",         # archivos estáticos
    "/media/",          # archivos subidos
    "/__debug__/",      # django-debug-toolbar
    "/favicon.ico",
)

_PENDING_URL = reverse_lazy("users:verify_pending")


class EmailVerificationMiddleware:
    """
    Redirige a usuarios autenticados pero no verificados a la página
    de verificación pendiente.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        if self._needs_redirect(request):
            return redirect(_PENDING_URL)
        return self.get_response(request)

    @staticmethod
    def _needs_redirect(request: HttpRequest) -> bool:
        # Solo aplica a usuarios autenticados.
        if not request.user.is_authenticated:
            return False

        # Usuarios verificados o staff pasan siempre.
        if getattr(request.user, "is_verified", True) or request.user.is_staff:
            return False

        # Rutas exentas.
        path = request.path_info
        if any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES):
            return False

        return True
