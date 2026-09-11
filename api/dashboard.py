"""Cached aggregate data used by public dashboard responses."""

from django.conf import settings
from django.core.cache import cache
from django.db.models import Count, Q

from .models import ScanLog, WhitelistDomain

DASHBOARD_CACHE_KEY = "dashboard:aggregates:v1"


def get_dashboard_aggregates():
    cached = cache.get(DASHBOARD_CACHE_KEY)
    if cached is not None:
        return cached

    scan_counts = ScanLog.objects.aggregate(
        total_scans=Count("id"),
        phishing_count=Count("id", filter=Q(status=ScanLog.Status.PHISHING)),
        safe_count=Count("id", filter=Q(status=ScanLog.Status.SAFE)),
        unknown_count=Count("id", filter=Q(status=ScanLog.Status.UNKNOWN)),
    )
    aggregates = {
        **scan_counts,
        "whitelist_count": WhitelistDomain.objects.filter(rank__gt=0).count(),
    }
    cache.set(
        DASHBOARD_CACHE_KEY,
        aggregates,
        timeout=settings.PHISHGUARD_STATS_CACHE_SECONDS,
    )
    return aggregates


def invalidate_dashboard_aggregates():
    cache.delete(DASHBOARD_CACHE_KEY)
