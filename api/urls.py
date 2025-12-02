from django.urls import path
from .views import analyze_url

urlpatterns = [
    path('predict/', analyze_url, name='predict'),
]