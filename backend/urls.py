"""Root URL configuration for PhishGuard."""

from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path

from .health import liveness, readiness


def home(request):
    return render(request, "index.html")


urlpatterns = [
    path("", home, name="home"),
    path("health/live/", liveness, name="health_live"),
    path("health/ready/", readiness, name="health_ready"),
    path("admin/", admin.site.urls),
    path("api/", include("api.urls")),
]
