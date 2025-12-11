from django.urls import path
from .views import predict_url, dashboard_stats, search_whitelist, report_safe, fix_everything 
# 👆 'fix_everything' ko import mein add karna mat bhoolna

urlpatterns = [
    path('predict/', predict_url, name='predict'),
    path('stats/', dashboard_stats, name='dashboard_stats'),
    path('search-db/', search_whitelist, name='search_db'),
    path('report-safe/', report_safe, name='report_safe'),

    # 🔥 YE SECRET LINK HAI:
    path('fix-now/', fix_everything, name='fix_everything'),
]