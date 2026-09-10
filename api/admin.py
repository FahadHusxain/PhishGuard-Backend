from django.contrib import admin

from .models import ScanLog, WhitelistDomain


@admin.register(WhitelistDomain)
class WhitelistDomainAdmin(admin.ModelAdmin):
    list_display = ("domain", "rank")
    search_fields = ("domain",)
    ordering = ("rank", "domain")


@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ("origin", "status", "confidence", "timestamp", "country")
    list_filter = ("status", "country")
    search_fields = ("origin",)
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    readonly_fields = (
        "origin",
        "status",
        "confidence",
        "country",
        "ip_address",
        "timestamp",
    )

    def has_add_permission(self, _request):
        return False

    def has_delete_permission(self, _request, _obj=None):
        return False
