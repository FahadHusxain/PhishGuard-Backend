"""Canonical URL configuration used to generate the public API schema."""

from django.urls import include, path

from api.urls import urlpatterns as api_urlpatterns

urlpatterns = [
    path(
        "api/v1/",
        include((api_urlpatterns, "api"), namespace="api-v1-schema"),
    )
]
