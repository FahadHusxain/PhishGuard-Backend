from django.urls import path

from .views import (
    analytics_view,
    dashboard_stats,
    predict_url,
    report_safe,
    search_whitelist,
)

urlpatterns = [
    path("predict/", predict_url, name="predict"),
    path("stats/", dashboard_stats, name="dashboard_stats"),
    path("search-db/", search_whitelist, name="search_db"),
    path("report-safe/", report_safe, name="report_safe"),
    path("analytics/", analytics_view, name="analytics"),
]
