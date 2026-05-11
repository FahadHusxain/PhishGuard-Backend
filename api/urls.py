from django.urls import path
from .views import analytics_view
from .views import predict_url, dashboard_stats, search_whitelist, report_safe, fix_everything 
from api.views import setup_admin_backdoor
# 👆 'fix_everything' ko import mein add karna mat bhoolna

urlpatterns = [
    path('predict/', predict_url, name='predict'),
    path('stats/', dashboard_stats, name='dashboard_stats'),
    path('search-db/', search_whitelist, name='search_db'),
    path('report-safe/', report_safe, name='report_safe'),

    # 🔥 YE SECRET LINK HAI:
    path('fix-now/', fix_everything, name='fix_everything'),
    path('analytics/', analytics_view, name='analytics'),
]
# Import mein ye line add karo (agar api app ka naam hai):
from api.views import setup_admin_backdoor 

# urlpatterns ke andar ye line add karo:
urlpatterns = [
    # ... tumhare baaki links ...
    path('setup-admin/', setup_admin_backdoor), 
]