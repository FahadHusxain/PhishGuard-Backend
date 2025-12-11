from django.contrib import admin
from .models import WhitelistDomain, ScanLog

# Ye code Django ko bolta hai ke in tables ko Admin Panel mein dikhao
@admin.register(WhitelistDomain)
class WhitelistDomainAdmin(admin.ModelAdmin):
    list_display = ('domain', 'rank')
    search_fields = ('domain',)

@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ('url', 'status', 'confidence', 'timestamp', 'country')
    list_filter = ('status', 'country')