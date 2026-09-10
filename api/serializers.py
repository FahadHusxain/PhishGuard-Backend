"""Validation for public API inputs."""

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from rest_framework import serializers


def normalize_hostname(hostname: str) -> str:
    """Return a canonical ASCII hostname or raise a validation error."""
    hostname = hostname.strip().rstrip(".").lower()
    if not hostname:
        raise serializers.ValidationError("The URL must include a hostname.")

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise serializers.ValidationError("The URL hostname is invalid.") from exc

    if len(ascii_hostname) > 253:
        raise serializers.ValidationError("The URL hostname is too long.")

    labels = ascii_hostname.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise serializers.ValidationError("The URL hostname is invalid.")

    return ascii_hostname


def hostname_from_url(url: str) -> str:
    """Extract and normalize a hostname from an already validated URL."""
    try:
        hostname = urlsplit(url).hostname or ""
    except ValueError as exc:
        raise serializers.ValidationError("The URL is malformed.") from exc
    return normalize_hostname(hostname)


def redact_url_for_storage(url: str) -> str:
    """Keep only a normalized URL origin, excluding paths, queries, and fragments."""
    parsed = urlsplit(url)
    hostname = hostname_from_url(url)
    rendered_hostname = f"[{hostname}]" if ":" in hostname else hostname
    netloc = rendered_hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


class URLSubmissionSerializer(serializers.Serializer):
    url = serializers.URLField(
        max_length=500,
        trim_whitespace=True,
    )

    def validate_url(self, value: str) -> str:
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise serializers.ValidationError("Only HTTP and HTTPS URLs are accepted.")
            if parsed.username is not None or parsed.password is not None:
                raise serializers.ValidationError(
                    "URLs containing embedded credentials are not accepted."
                )
            hostname_from_url(value)
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise serializers.ValidationError("The URL port is invalid.")
        except ValueError as exc:
            raise serializers.ValidationError("The URL is malformed.") from exc
        return value


class WhitelistSearchSerializer(serializers.Serializer):
    q = serializers.CharField(max_length=253, min_length=2, trim_whitespace=True)

    def validate_q(self, value: str) -> str:
        value = value.lower().rstrip(".")
        if not all(character.isalnum() or character in ".-" for character in value):
            raise serializers.ValidationError("Enter a valid domain fragment.")
        return value
