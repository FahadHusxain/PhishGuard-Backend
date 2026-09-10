"""Root URL configuration for PhishGuard."""

from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from api.urls import urlpatterns as api_urlpatterns

from .health import liveness, readiness


def home(request):
    return render(request, "index.html")


urlpatterns = [
    path("", home, name="home"),
    path("health/live/", liveness, name="health_live"),
    path("health/ready/", readiness, name="health_ready"),
    path("admin/", admin.site.urls),
    path(
        "api/schema/",
        SpectacularAPIView.as_view(urlconf="backend.api_v1_urls"),
        name="api_schema",
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="api_schema"),
        name="api_docs",
    ),
    path(
        "api/v1/",
        include((api_urlpatterns, "api"), namespace="api-v1"),
    ),
    path("api/", include("api.urls")),
]
