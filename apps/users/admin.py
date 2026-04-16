"""
Admin del modelo User.

Extendemos UserAdmin (no lo reescribimos) para aprovechar toda la
lógica de cambio de password, gestión de permisos, etc., y solo
ajustamos los fieldsets para que reflejen nuestros campos (email
en vez de username, plan nuevo).
"""
from __future__ import annotations

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    ordering = ("email",)
    list_display = ("email", "plan", "is_staff", "is_active", "date_joined")
    list_filter = ("plan", "is_staff", "is_active")
    search_fields = ("email", "first_name", "last_name")

    # Fieldsets para la vista de edición.
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Información personal"), {"fields": ("first_name", "last_name")}),
        (_("Plan"), {"fields": ("plan",)}),
        (
            _("Permisos"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (_("Fechas importantes"), {"fields": ("last_login", "date_joined")}),
    )

    # Fieldsets para la vista de creación (desde el admin).
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2", "plan"),
            },
        ),
    )
