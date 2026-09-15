"""Exact URL threat-intelligence matching without retaining submitted URLs."""

import hashlib
import logging
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.db import DatabaseError
from django.utils import timezone

from .domains import normalize_hostname
from .models import ThreatFeedSnapshot, ThreatIndicator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ThreatMatch:
    source: str
    retrieved_at: object


def canonicalize_indicator_url(url: str) -> str:
    """Produce the stable exact-match form used by ingestion and prediction."""
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Indicator must be a complete HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Indicators containing embedded credentials are rejected.")
    hostname = normalize_hostname(parsed.hostname)
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Indicator contains an invalid port.") from exc
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        rendered_host = f"{rendered_host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, rendered_host, path, parsed.query, ""))


def indicator_digest(url: str) -> str:
    canonical = canonicalize_indicator_url(url)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def find_active_threat(url: str) -> ThreatMatch | None:
    """Return a match only when its source snapshot is still fresh."""
    if not settings.PHISHGUARD_THREAT_INTELLIGENCE_ENABLED:
        return None
    digest = indicator_digest(url)
    cutoff = timezone.now() - timedelta(
        hours=settings.PHISHGUARD_THREAT_FEED_MAX_AGE_HOURS
    )
    try:
        indicator = (
            ThreatIndicator.objects.filter(
                url_sha256=digest,
                active=True,
                source__in=ThreatFeedSnapshot.objects.filter(
                    retrieved_at__gte=cutoff
                ).values("source"),
            )
            .order_by("source")
            .first()
        )
        if indicator is None:
            return None
        snapshot = ThreatFeedSnapshot.objects.only("retrieved_at").get(
            source=indicator.source
        )
    except DatabaseError:
        logger.exception("Threat-intelligence lookup failed")
        return None
    return ThreatMatch(source=indicator.source, retrieved_at=snapshot.retrieved_at)
