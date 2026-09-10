"""Canonical hostname handling shared by API, models, and import jobs."""

import ipaddress

import tldextract
from django.core.exceptions import ValidationError

_SUFFIX_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def normalize_hostname(hostname: str) -> str:
    """Return a canonical ASCII hostname or raise a Django validation error."""
    hostname = hostname.strip().rstrip(".").lower()
    if not hostname:
        raise ValidationError("The URL must include a hostname.")

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("The URL hostname is invalid.") from exc

    if len(ascii_hostname) > 253:
        raise ValidationError("The URL hostname is too long.")

    labels = ascii_hostname.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise ValidationError("The URL hostname is invalid.")

    return ascii_hostname


def registrable_domain(hostname: str) -> str | None:
    """Return the smallest privately registrable domain for a hostname."""
    hostname = normalize_hostname(hostname)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        extracted = _SUFFIX_EXTRACTOR(hostname)
        return extracted.top_domain_under_public_suffix or None
    return hostname


def normalize_whitelist_domain(hostname: str) -> str:
    """Canonicalize a whitelist entry and reject shared suffix boundaries."""
    hostname = normalize_hostname(hostname)
    if registrable_domain(hostname) is None:
        raise ValidationError(
            "A public suffix cannot be added to the trusted whitelist."
        )
    return hostname


def whitelist_candidates(hostname: str) -> list[str]:
    """Return exact-to-registrable candidates without crossing ownership bounds."""
    hostname = normalize_hostname(hostname)
    boundary = registrable_domain(hostname)
    if boundary is None:
        return [hostname]

    labels = hostname.split(".")
    boundary_labels = boundary.split(".")
    final_start = len(labels) - len(boundary_labels)
    return [".".join(labels[index:]) for index in range(final_start + 1)]
