"""HTTP views for the PhishGuard API and dashboard."""

import ipaddress
import logging
import socket

import requests
from django.conf import settings
from django.db import DatabaseError, transaction
from django.shortcuts import render
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .dashboard import get_dashboard_aggregates
from .domains import whitelist_candidates
from .ml_logic import predict_url_security
from .models import ScanLog, WhitelistAuditEvent, WhitelistDomain
from .permissions import CanManageWhitelist, can_view_scan_activity
from .serializers import (
    DashboardStatsSerializer,
    ErrorEnvelopeSerializer,
    PredictionResponseSerializer,
    ReportSafeResponseSerializer,
    URLSubmissionSerializer,
    WhitelistResultSerializer,
    WhitelistSearchSerializer,
    WhitelistSubmissionSerializer,
    hostname_from_url,
    redact_url_for_storage,
)
from .throttles import (
    AdministrationRateThrottle,
    AnalysisRateThrottle,
    ReadRateThrottle,
)

logger = logging.getLogger(__name__)


def _public_ip_for_hostname(hostname: str) -> str | None:
    """Resolve a hostname only when every returned address is globally routable."""
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return None

    addresses = {record[4][0] for record in records}
    if not addresses:
        return None

    parsed_addresses = []
    for address in addresses:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            return None
        if not parsed_address.is_global:
            return None
        parsed_addresses.append(parsed_address)

    return str(min(parsed_addresses, key=lambda item: (item.version, int(item))))


def get_ip_location(url: str) -> tuple[str | None, str]:
    """Resolve optional geolocation without contacting user-controlled hosts."""
    if not settings.PHISHGUARD_GEOLOCATION_ENABLED:
        return None, "Unknown"

    hostname = hostname_from_url(url)
    ip_address = _public_ip_for_hostname(hostname)
    if ip_address is None:
        return None, "Unknown"

    try:
        response = requests.get(
            f"https://ipapi.co/{ip_address}/country_name/",
            headers={"User-Agent": "PhishGuard/1.0"},
            timeout=settings.PHISHGUARD_GEOLOCATION_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        country = response.text.strip()
        if not country or len(country) > 50:
            country = "Unknown"
    except requests.RequestException:
        country = "Unknown"

    return ip_address, country


def _listed_domain(hostname: str) -> WhitelistDomain | None:
    return (
        WhitelistDomain.objects.filter(
            domain__in=whitelist_candidates(hostname),
            rank__gt=0,
        )
        .order_by("-rank")
        .first()
    )


@extend_schema(
    operation_id="analyze_url",
    summary="Analyze a URL for phishing risk",
    request=URLSubmissionSerializer,
    responses={
        200: PredictionResponseSerializer,
        400: ErrorEnvelopeSerializer,
        413: ErrorEnvelopeSerializer,
        415: ErrorEnvelopeSerializer,
        429: ErrorEnvelopeSerializer,
    },
    tags=["Analysis"],
)
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AnalysisRateThrottle])
def predict_url(request):
    serializer = URLSubmissionSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    url = serializer.validated_data["url"]
    hostname = hostname_from_url(url)
    stored_url = redact_url_for_storage(url)

    listed_domain = _listed_domain(hostname)
    result = predict_url_security(url)
    result["domain_listed"] = listed_domain is not None
    result["domain_context"] = (
        "Domain matches the reference list. Membership does not verify this page."
        if listed_domain is not None
        else "No active domain-list match. Absence does not imply phishing."
    )
    ip_address, country = get_ip_location(url)

    try:
        ScanLog.objects.create(
            origin=stored_url,
            status=result["status"],
            confidence=result["confidence"],
            ip_address=ip_address,
            country=country,
        )
    except DatabaseError:
        logger.exception("Unable to store a URL scan result")

    return Response({**result, "country": country})


@extend_schema(
    operation_id="add_trusted_domain",
    summary="Add a domain to the reviewed reference list",
    request=WhitelistSubmissionSerializer,
    responses={
        200: ReportSafeResponseSerializer,
        201: ReportSafeResponseSerializer,
        400: ErrorEnvelopeSerializer,
        403: ErrorEnvelopeSerializer,
        413: ErrorEnvelopeSerializer,
        415: ErrorEnvelopeSerializer,
        429: ErrorEnvelopeSerializer,
    },
    tags=["Administration"],
)
@api_view(["POST"])
@permission_classes([CanManageWhitelist])
@throttle_classes([AdministrationRateThrottle])
@transaction.atomic
def report_safe(request):
    serializer = WhitelistSubmissionSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    hostname = hostname_from_url(serializer.validated_data["url"])
    whitelist_entry, created = (
        WhitelistDomain.objects.select_for_update().get_or_create(
            domain=hostname,
            defaults={"rank": 50},
        )
    )

    action = WhitelistAuditEvent.Action.ADDED if created else None
    previous_rank = None if created else whitelist_entry.rank
    if not created and previous_rank <= 0:
        whitelist_entry.rank = 50
        whitelist_entry.save(update_fields=["rank"])
        action = WhitelistAuditEvent.Action.PROMOTED

    if action is not None:
        WhitelistAuditEvent.objects.create(
            domain=hostname,
            action=action,
            actor=request.user,
            actor_username=request.user.get_username(),
            previous_rank=previous_rank,
            new_rank=whitelist_entry.rank,
            reason=serializer.validated_data["reason"],
            request_id=request.request_id,
        )

    response_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return Response(
        {"status": "Whitelisted", "domain": hostname},
        status=response_status,
    )


@extend_schema(
    operation_id="dashboard_statistics",
    summary="Get aggregate scan statistics",
    responses={200: DashboardStatsSerializer, 429: ErrorEnvelopeSerializer},
    tags=["Statistics"],
)
@api_view(["GET"])
@permission_classes([AllowAny])
@throttle_classes([ReadRateThrottle])
def dashboard_stats(request):
    aggregates = get_dashboard_aggregates()
    recent_logs_visible = can_view_scan_activity(request.user)
    recent_scan_rows = ScanLog.objects.all()[:10] if recent_logs_visible else []
    recent_logs = []
    for scan in recent_scan_rows:
        try:
            domain = hostname_from_url(scan.origin)
        except (ValueError, ValidationError):
            domain = "invalid-domain"
        recent_logs.append(
            {
                "domain": domain,
                "status": scan.status,
                "confidence": scan.confidence,
                "timestamp": scan.timestamp,
                "country": scan.country,
            }
        )

    return Response(
        {
            **aggregates,
            "recent_logs_visible": recent_logs_visible,
            "recent_logs": recent_logs,
            "graph_data": [],
        }
    )


@extend_schema(
    operation_id="search_listed_domains",
    summary="Search the domain reference list",
    parameters=[WhitelistSearchSerializer],
    responses={
        200: WhitelistResultSerializer(many=True),
        400: ErrorEnvelopeSerializer,
        429: ErrorEnvelopeSerializer,
    },
    tags=["Domain reference"],
)
@api_view(["GET"])
@permission_classes([AllowAny])
@throttle_classes([ReadRateThrottle])
def search_whitelist(request):
    serializer = WhitelistSearchSerializer(data=request.query_params)
    serializer.is_valid(raise_exception=True)
    query = serializer.validated_data["q"]
    results = WhitelistDomain.objects.filter(
        domain__startswith=query,
        rank__gt=0,
    ).order_by("rank", "domain")[:20]
    return Response([{"domain": entry.domain, "rank": entry.rank} for entry in results])


def analytics_view(request):
    return render(request, "stats.html")
