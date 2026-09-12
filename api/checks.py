"""Deployment checks for security controls that depend on shared state."""

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register
from django.core.exceptions import ImproperlyConfigured

from .ml_logic import _load_shadow_classifier
from .throttles import (
    AdministrationRateThrottle,
    AnalysisRateThrottle,
    ReadRateThrottle,
)
from .verified_platforms import verified_platform_domains

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


@register(Tags.security)
def shadow_model_configuration_check(app_configs, **_kwargs):
    if not settings.PHISHGUARD_ML_SHADOW_ENABLED:
        return []
    _load_shadow_classifier.cache_clear()
    if _load_shadow_classifier() is not None:
        return []
    return [
        Error(
            "The enabled v4 shadow model failed its integrity check.",
            hint="Restore the frozen v4 artifacts or disable shadow mode.",
            id="api.E002",
        )
    ]


@register(Tags.security)
def verified_platform_registry_check(app_configs, **_kwargs):
    verified_platform_domains.cache_clear()
    try:
        domains = verified_platform_domains()
    except (OSError, TypeError, ValueError) as exc:
        return [
            Error(
                "The verified-platform registry is invalid.",
                hint=str(exc),
                id="api.E003",
            )
        ]
    if domains:
        return []
    return [
        Error(
            "The verified-platform registry is empty.",
            hint="Add reviewed platform records or remove the low-risk policy.",
            id="api.E003",
        )
    ]
