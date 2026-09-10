"""Hybrid URL risk scoring backed by the committed character-level CNN."""

import ipaddress
import logging
import re
from functools import lru_cache
from urllib.parse import unquote, urlsplit

from django.conf import settings

from .domains import normalize_hostname, registrable_domain
from .ml_classifier import ModelLoadError, URLCNNClassifier

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = frozenset(
    {
        "account",
        "bank",
        "login",
        "password",
        "secure",
        "signin",
        "update",
        "verify",
        "wallet",
        "unlock",
    }
)

NESTED_URL_PATTERN = re.compile(r"(?:https?%3a|https?://)", re.IGNORECASE)


def _tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", unquote(value).lower()) if token}


def _rule_assessment(url: str) -> tuple[float, list[str]]:
    parsed = urlsplit(url)
    hostname = normalize_hostname(parsed.hostname or "")
    registered = registrable_domain(hostname)
    host_tokens = _tokens(hostname)
    resource_tokens = _tokens(f"{parsed.path}?{parsed.query}")
    host_lures = host_tokens & SUSPICIOUS_KEYWORDS
    resource_lures = resource_tokens & SUSPICIOUS_KEYWORDS
    score = 0.0
    reasons = []

    if parsed.scheme.lower() == "http" and (host_lures or resource_lures):
        score += 30
        reasons.append("Sensitive page is served over unencrypted HTTP")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        score += 45
        reasons.append("URL uses an IP address instead of a domain")

    if len(host_lures) >= 2:
        score += 40
        reasons.append("Hostname combines multiple credential-theft lure terms")
    elif host_lures:
        score += 25
        reasons.append("Hostname contains a credential-theft lure term")

    if len(resource_lures) >= 2:
        score += 15
        reasons.append("Page path contains multiple credential-related terms")
    elif resource_lures:
        score += 8

    if NESTED_URL_PATTERN.search(parsed.query):
        score += 25
        reasons.append("Query embeds another URL and may conceal a redirect")

    if len(url) > 200:
        score += 15
        reasons.append("URL is unusually long")
    elif len(url) > 120:
        score += 8

    if "@" in parsed.path or "@" in parsed.query:
        score += 15
        reasons.append("URL contains a misleading @ character")

    if registered and hostname != registered:
        subdomain_depth = len(hostname.split(".")) - len(registered.split("."))
    else:
        subdomain_depth = 0
    if subdomain_depth >= 4:
        score += 25
        reasons.append("Hostname has an extremely deep subdomain chain")
    elif subdomain_depth >= 2:
        score += 15
        reasons.append("Hostname has an unusually deep subdomain chain")

    if any(label.startswith("xn--") for label in hostname.split(".")):
        score += 15
        reasons.append("Hostname uses internationalized-domain encoding")

    if hostname.count("-") >= 4:
        score += 10
        reasons.append("Hostname contains many hyphens")

    hostname_characters = hostname.replace(".", "").replace("-", "")
    if len(hostname_characters) >= 10:
        digit_ratio = sum(
            character.isdigit() for character in hostname_characters
        ) / len(hostname_characters)
        if digit_ratio >= 0.3:
            score += 10
            reasons.append("Hostname contains an unusual concentration of digits")

    if url.count("%") >= 3:
        score += 10
        reasons.append("URL contains heavy percent encoding")

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None and port not in {80, 443}:
        score += 10
        reasons.append("URL uses a nonstandard network port")

    return min(score, 100.0), reasons


@lru_cache(maxsize=1)
def _load_classifier() -> URLCNNClassifier | None:
    if not settings.PHISHGUARD_ML_ENABLED:
        return None

    try:
        return URLCNNClassifier(
            settings.PHISHGUARD_MODEL_PATH,
            settings.PHISHGUARD_TOKENIZER_PATH,
        )
    except ModelLoadError:
        logger.exception("PhishGuard CNN could not be loaded; using rules-only mode")
        return None


def _model_probability(url: str) -> float | None:
    classifier = _load_classifier()
    if classifier is None:
        return None
    return classifier.predict_probability(url)


def predict_url_security(url: str) -> dict[str, str | float | list[str]]:
    """Classify a validated URL and explain which detection engine was used."""
    rule_risk, reasons = _rule_assessment(url)
    model_probability = _model_probability(url)

    if model_probability is None:
        engine = "rules-only"
        risk_score = rule_risk
    else:
        engine = "hybrid-cnn-rules"
        model_risk = model_probability * 100.0
        risk_score = (
            settings.PHISHGUARD_ML_WEIGHT * model_risk
            + (1.0 - settings.PHISHGUARD_ML_WEIGHT) * rule_risk
        )

    risk_score = min(max(risk_score, 0.0), 100.0)
    is_phishing = risk_score >= settings.PHISHGUARD_PHISHING_THRESHOLD

    if is_phishing:
        status = "PHISHING"
        confidence = risk_score
    elif engine == "rules-only":
        status = "UNKNOWN"
        confidence = 0.0
    else:
        status = "SAFE"
        confidence = 100.0 - risk_score

    if reasons:
        message = "; ".join(reasons[:3])
    elif status == "PHISHING":
        message = "The URL model detected a phishing pattern"
    elif status == "UNKNOWN":
        message = "The ML model is unavailable and no high-risk rule matched"
    else:
        message = "No high-risk URL patterns were detected"

    result: dict[str, str | float | list[str]] = {
        "status": status,
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 2),
        "message": message,
        "engine": engine,
        "signals": reasons,
    }
    if model_probability is not None:
        result["model_risk_score"] = round(model_probability * 100.0, 2)
        result["rule_risk_score"] = round(rule_risk, 2)
    return result
