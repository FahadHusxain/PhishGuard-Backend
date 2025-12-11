from django.urls import path
from .views import predict_url, dashboard_stats, search_whitelist

urlpatterns = [
    path('predict/', predict_url, name='predict'),             # For Extension/Console
    path('stats/', dashboard_stats, name='dashboard_stats'),   # For Dashboard Numbers
    path('search-db/', search_whitelist, name='search_db'),    # For Intel DB Search
    path('report-safe/', report_safe, name='report_safe'),
]