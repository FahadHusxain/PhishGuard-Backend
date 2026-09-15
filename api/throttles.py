"""Endpoint-specific request budgets backed by Django's shared cache."""

from rest_framework.throttling import UserRateThrottle


class AnalysisRateThrottle(UserRateThrottle):
    scope = "analysis"


class AdministrationRateThrottle(UserRateThrottle):
    scope = "administration"


class ReadRateThrottle(UserRateThrottle):
    scope = "read"
