"""Conservative, reviewable policy for known official platform root pages."""

import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings

from .domains import normalize_hostname


@lru_cache(maxsize=1)
def verified_platform_domains() -> frozenset[str]:
    registry_path = Path(settings.PHISHGUARD_VERIFIED_PLATFORMS_PATH)
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    if document.get("format_version") != 1:
        raise ValueError("Unsupported verified-platform registry format")
    domains = []
    for entry in document["platforms"]:
        domain = normalize_hostname(entry["domain"])
        official_url = urlsplit(entry["official_url"])
        official_hostname = normalize_hostname(official_url.hostname or "")
        if (
            official_url.scheme != "https"
            or official_url.path not in {"", "/"}
            or official_url.query
            or official_url.fragment
            or official_hostname not in {domain, f"www.{domain}"}
        ):
            raise ValueError(f"Invalid official URL for verified platform {domain}")
        domains.append(domain)
    if len(domains) != len(set(domains)):
        raise ValueError("Verified-platform registry contains duplicate domains")
    return frozenset(domains)


def is_verified_platform_root(url: str) -> bool:
    """Return true only for an exact, HTTPS, reviewed platform root URL."""
    parsed = urlsplit(url)
    hostname = normalize_hostname(parsed.hostname or "")
    try:
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or port not in {None, 443}:
        return False
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return False
    candidates = verified_platform_domains()
    return hostname in candidates or (
        hostname.startswith("www.") and hostname[4:] in candidates
    )
