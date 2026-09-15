from django.contrib import admin

from .models import (
    ScanLog,
    ThreatFeedSnapshot,
    ThreatIndicator,
    WhitelistAuditEvent,
    WhitelistDomain,
)

admin.site.site_header = "PhishGuard secure command"
admin.site.site_title = "PhishGuard Administration"
admin.site.index_title = "Defense data controls"


@admin.register(WhitelistDomain)
class WhitelistDomainAdmin(admin.ModelAdmin):
    list_display = ("domain", "rank")
    search_fields = ("domain",)
    ordering = ("rank", "domain")


@admin.register(WhitelistAuditEvent)
class WhitelistAuditEventAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "domain",
        "action",
        "actor_username",
        "previous_rank",
        "new_rank",
    )
    list_filter = ("action", "timestamp")
    search_fields = ("domain", "actor_username", "request_id")
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    readonly_fields = (
        "domain",
        "action",
        "actor",
        "actor_username",
        "previous_rank",
        "new_rank",
        "reason",
        "request_id",
        "timestamp",
    )

    def has_add_permission(self, _request):
        return False

    def has_change_permission(self, _request, _obj=None):
        return False

    def has_delete_permission(self, _request, _obj=None):
        return False


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


@admin.register(ThreatFeedSnapshot)
class ThreatFeedSnapshotAdmin(admin.ModelAdmin):
    list_display = ("source", "retrieved_at", "imported_at", "indicator_count")
    readonly_fields = (
        "source",
        "retrieved_at",
        "imported_at",
        "content_sha256",
        "indicator_count",
    )

    def has_add_permission(self, _request):
        return False

    def has_change_permission(self, _request, _obj=None):
        return False

    def has_delete_permission(self, _request, _obj=None):
        return False


@admin.register(ThreatIndicator)
class ThreatIndicatorAdmin(admin.ModelAdmin):
    list_display = ("source", "digest_prefix", "active", "last_seen")
    list_filter = ("source", "active")
    readonly_fields = ("source", "url_sha256", "first_seen", "last_seen", "active")

    @admin.display(description="URL digest")
    def digest_prefix(self, obj):
        return f"{obj.url_sha256[:16]}..."

    def has_add_permission(self, _request):
        return False

    def has_change_permission(self, _request, _obj=None):
        return False

    def has_delete_permission(self, _request, _obj=None):
        return False
