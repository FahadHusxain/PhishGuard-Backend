from django.urls import path
from .views import predict_url, dashboard_stats, search_whitelist, report_safe

# Note: Upar 'report_safe' import karna mat bhoolna! 👆

urlpatterns = [
    path('predict/', predict_url, name='predict'),
    path('stats/', dashboard_stats, name='dashboard_stats'),
    path('search-db/', search_whitelist, name='search_db'),
    
    # 🔥 YE LINE MISSING THI, ISLIYE ERROR AA RAHA THA:
    path('report-safe/', report_safe, name='report_safe'),
]