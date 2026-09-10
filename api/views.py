"""HTTP views for the PhishGuard API and dashboard."""

import ipaddress
import logging
import socket

import requests
from django.conf import settings
from django.db import DatabaseError
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from .ml_logic import predict_url_security
from .models import ScanLog, WhitelistDomain
from .serializers import (
    URLSubmissionSerializer,
    WhitelistSearchSerializer,
    hostname_from_url,
    redact_url_for_storage,
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


def _whitelist_candidates(hostname: str) -> list[str]:
    """Build exact hostname and parent-domain candidates for whitelist lookup."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.split(".")
        return [".".join(labels[index:]) for index in range(max(len(labels) - 1, 1))]
    return [hostname]


def _trusted_domain(hostname: str) -> WhitelistDomain | None:
    return (
        WhitelistDomain.objects.filter(
            domain__in=_whitelist_candidates(hostname),
            rank__gt=0,
        )
        .order_by("-rank")
        .first()
    )


@api_view(["POST"])
def predict_url(request):
    serializer = URLSubmissionSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    url = serializer.validated_data["url"]
    hostname = hostname_from_url(url)
    stored_url = redact_url_for_storage(url)

    if _trusted_domain(hostname):
        result = {
            "status": "SAFE",
            "confidence": 100,
            "message": "Domain is in the trusted whitelist",
            "country": "Whitelisted",
        }
        ScanLog.objects.create(
            url=stored_url,
            status=result["status"],
            confidence=result["confidence"],
            ip_address=None,
            country="Whitelisted",
        )
        return Response(result)

    result = predict_url_security(url)
    ip_address, country = get_ip_location(url)

    try:
        ScanLog.objects.create(
            url=stored_url,
            status=result["status"],
            confidence=result["confidence"],
            ip_address=ip_address,
            country=country,
        )
    except DatabaseError:
        logger.exception("Unable to store a URL scan result")

    return Response({**result, "country": country})


@api_view(["POST"])
@permission_classes([IsAdminUser])
def report_safe(request):
    serializer = URLSubmissionSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    hostname = hostname_from_url(serializer.validated_data["url"])
    whitelist_entry, created = WhitelistDomain.objects.get_or_create(
        domain=hostname,
        defaults={"rank": 50},
    )

    if not created and whitelist_entry.rank <= 0:
        whitelist_entry.rank = 50
        whitelist_entry.save(update_fields=["rank"])

    response_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return Response(
        {"status": "Whitelisted", "domain": hostname},
        status=response_status,
    )


@api_view(["GET"])
def dashboard_stats(request):
    recent_scan_rows = ScanLog.objects.order_by("-timestamp")[:10]
    recent_logs = []
    for scan in recent_scan_rows:
        try:
            domain = hostname_from_url(scan.url)
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
            "total_scans": ScanLog.objects.count(),
            "phishing_count": ScanLog.objects.filter(status="PHISHING").count(),
            "safe_count": ScanLog.objects.filter(status="SAFE").count(),
            "unknown_count": ScanLog.objects.filter(status="UNKNOWN").count(),
            "whitelist_count": WhitelistDomain.objects.count(),
            "recent_logs": recent_logs,
            "graph_data": [],
        }
    )


@api_view(["GET"])
def search_whitelist(request):
    serializer = WhitelistSearchSerializer(data=request.query_params)
    serializer.is_valid(raise_exception=True)
    query = serializer.validated_data["q"]
    results = WhitelistDomain.objects.filter(domain__icontains=query).order_by(
        "-rank", "domain"
    )[:20]
    return Response([{"domain": entry.domain, "rank": entry.rank} for entry in results])


def analytics_view(request):
    return render(request, "stats.html")
