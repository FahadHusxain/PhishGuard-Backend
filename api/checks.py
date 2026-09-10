"""Deployment checks for security controls that depend on shared state."""

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register
from django.core.exceptions import ImproperlyConfigured

from .throttles import (
    AdministrationRateThrottle,
    AnalysisRateThrottle,
    ReadRateThrottle,
)

THROTTLE_CLASSES = (
    AnalysisRateThrottle,
    AdministrationRateThrottle,
    ReadRateThrottle,
)


@register()
def throttle_rate_configuration_check(app_configs, **_kwargs):
    for throttle_class in THROTTLE_CLASSES:
        try:
            throttle_class()
        except (ImproperlyConfigured, KeyError, TypeError, ValueError) as exc:
            return [
                Error(
                    f"Invalid rate for throttle scope '{throttle_class.scope}'.",
                    hint=str(exc),
                    id="api.E001",
                )
            ]
    return []


@register(Tags.security, deploy=True)
def shared_throttle_cache_check(app_configs, **_kwargs):
    if settings.DEBUG or settings.CACHE_URL:
        return []
    return [
        Warning(
            "Rate limits use a process-local cache.",
            hint=(
                "Set CACHE_URL to a shared Redis instance when running multiple "
                "workers or replicas."
            ),
            id="api.W001",
        )
    ]
