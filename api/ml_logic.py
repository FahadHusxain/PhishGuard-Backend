"""Hybrid URL risk scoring backed by the committed character-level CNN."""

import ipaddress
import logging
from functools import lru_cache
from urllib.parse import urlsplit

from django.conf import settings

from .ml_classifier import ModelLoadError, URLCNNClassifier

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}


def _rule_assessment(url: str) -> tuple[float, list[str]]:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    url_lower = url.lower()
    score = 0.0
    reasons = []

    has_sensitive_keyword = any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS)
    if parsed.scheme.lower() == "http" and has_sensitive_keyword:
        score += 40
        reasons.append("Sensitive page is served over unencrypted HTTP")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        score += 55
        reasons.append("URL uses an IP address instead of a domain")

    if len(url) > 100:
        score += 15
        reasons.append("URL is unusually long")
    if "@" in parsed.path or "@" in parsed.query:
        score += 20
        reasons.append("URL contains a misleading @ character")
    if hostname.count(".") >= 4:
        score += 15
        reasons.append("Hostname has an unusually deep subdomain chain")
    if any(label.startswith("xn--") for label in hostname.split(".")):
        score += 20
        reasons.append("Hostname uses internationalized-domain encoding")
    if hostname.count("-") >= 3:
        score += 15
        reasons.append("Hostname contains many hyphens")

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


def predict_url_security(url: str) -> dict[str, str | float]:
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

    result: dict[str, str | float] = {
        "status": status,
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 2),
        "message": message,
        "engine": engine,
    }
    if model_probability is not None:
        result["model_risk_score"] = round(model_probability * 100.0, 2)
        result["rule_risk_score"] = round(rule_risk, 2)
    return result
