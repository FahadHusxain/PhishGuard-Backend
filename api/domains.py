"""Canonical hostname handling shared by API, models, and import jobs."""

import ipaddress

from django.core.exceptions import ValidationError


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
