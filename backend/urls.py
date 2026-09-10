"""Root URL configuration for PhishGuard."""

from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path


def home(request):
    return render(request, "index.html")


urlpatterns = [
    path("", home, name="home"),
    path("admin/", admin.site.urls),
    path("api/", include("api.urls")),
]
