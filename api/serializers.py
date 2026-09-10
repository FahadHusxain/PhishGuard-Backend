"""Validation for public API inputs."""

from urllib.parse import urlsplit, urlunsplit

from rest_framework import serializers

from .domains import normalize_hostname, normalize_whitelist_domain


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
                raise serializers.ValidationError(
                    "Only HTTP and HTTPS URLs are accepted."
                )
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


class WhitelistSubmissionSerializer(URLSubmissionSerializer):
    reason = serializers.CharField(
        max_length=500,
        required=False,
        default="Administrative review",
        trim_whitespace=True,
    )

    def validate_url(self, value: str) -> str:
        value = super().validate_url(value)
        hostname = hostname_from_url(value)
        normalize_whitelist_domain(hostname)
        return value


class WhitelistSearchSerializer(serializers.Serializer):
    q = serializers.CharField(max_length=253, min_length=2, trim_whitespace=True)

    def validate_q(self, value: str) -> str:
        value = value.lower().rstrip(".")
        if not all(character.isalnum() or character in ".-" for character in value):
            raise serializers.ValidationError("Enter a valid domain fragment.")
        return value


class PredictionResponseSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["SAFE", "PHISHING", "UNKNOWN"])
    confidence = serializers.FloatField(min_value=0, max_value=100)
    risk_score = serializers.FloatField(min_value=0, max_value=100, required=False)
    message = serializers.CharField()
    country = serializers.CharField()
    engine = serializers.ChoiceField(
        choices=["rules-only", "hybrid-cnn-rules"],
        required=False,
    )
    model_risk_score = serializers.FloatField(
        min_value=0,
        max_value=100,
        required=False,
    )
    rule_risk_score = serializers.FloatField(
        min_value=0,
        max_value=100,
        required=False,
    )
    signals = serializers.ListField(
        child=serializers.CharField(),
        required=False,
    )


class WhitelistResultSerializer(serializers.Serializer):
    domain = serializers.CharField()
    rank = serializers.IntegerField(min_value=0)


class ReportSafeResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    domain = serializers.CharField()


class RecentScanSerializer(serializers.Serializer):
    domain = serializers.CharField()
    status = serializers.ChoiceField(choices=["SAFE", "PHISHING", "UNKNOWN"])
    confidence = serializers.FloatField(min_value=0, max_value=100)
    timestamp = serializers.DateTimeField()
    country = serializers.CharField()


class DashboardStatsSerializer(serializers.Serializer):
    total_scans = serializers.IntegerField(min_value=0)
    phishing_count = serializers.IntegerField(min_value=0)
    safe_count = serializers.IntegerField(min_value=0)
    unknown_count = serializers.IntegerField(min_value=0)
    whitelist_count = serializers.IntegerField(min_value=0)
    recent_logs = RecentScanSerializer(many=True)
    graph_data = serializers.ListField(child=serializers.JSONField())


class ErrorDetailSerializer(serializers.Serializer):
    code = serializers.CharField()
    message = serializers.CharField()
    details = serializers.JSONField()


class ErrorEnvelopeSerializer(serializers.Serializer):
    error = ErrorDetailSerializer()
    request_id = serializers.CharField(allow_null=True)
