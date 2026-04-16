"""Admin de audits y findings."""
from __future__ import annotations

from django.contrib import admin

from .models import Audit, Finding


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    fields = ("severity", "category", "title")
    readonly_fields = fields
    can_delete = False
    show_change_link = True


@admin.register(Audit)
class AuditAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "target_url",
        "status",
        "score",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("target_url", "user__email")
    readonly_fields = (
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "raw_data",
    )
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("id", "audit", "severity", "category", "title")
    list_filter = ("severity", "category")
    search_fields = ("title", "description")
