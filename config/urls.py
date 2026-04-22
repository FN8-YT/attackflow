"""URLs raíz del proyecto."""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.views.generic import RedirectView

from apps.users.forms import EmailAuthenticationForm

urlpatterns = [
    # Panel de administración de Django.
    path("admin/", admin.site.urls),

    # Raíz: redirige al dashboard. Si no está logueado, el decorador
    # @login_required del dashboard lo rebota a /accounts/login/.
    path(
        "",
        RedirectView.as_view(pattern_name="users:dashboard", permanent=False),
        name="home",
    ),

    # Login/logout: usamos las vistas built-in de Django.
    # EmailAuthenticationForm solo renombra la etiqueta a "Email".
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(
            authentication_form=EmailAuthenticationForm,
            redirect_authenticated_user=True,
        ),
        name="login",
    ),
    path(
        "accounts/logout/",
        auth_views.LogoutView.as_view(),
        name="logout",
    ),

    # Rutas propias de la app users (register, dashboard).
    path("accounts/", include("apps.users.urls")),

    # Auditorías
    path("audits/", include("apps.audits.urls")),

    # Reportes (PDF export, etc.)
    path("reports/", include("apps.reports.urls")),

    # Continuous Monitoring
    path("monitoring/", include("apps.monitoring.urls")),
]
