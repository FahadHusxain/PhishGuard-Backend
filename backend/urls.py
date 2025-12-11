"""
URL configuration for backend project.
"""
from django.contrib import admin
from django.urls import path, include
from api.views import home  # <--- 1. YE LINE ADD HUWI HAI
from django.shortcuts import render
# ... baaki imports ...

# ... baaki functions ...

def home(request):
    return render(request, 'index.html')

urlpatterns = [
    # 2. YE LINE ADD HUWI HAI (Homepage ke liye)
    path('', home, name='home'),
    
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
]