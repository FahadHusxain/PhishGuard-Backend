from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class WhitelistDomain(models.Model):
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    rank = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ("rank", "domain")
        constraints = (
            models.CheckConstraint(
                condition=models.Q(rank__gte=0),
                name="whitelist_rank_nonnegative",
            ),
        )

    def __str__(self):
        return self.domain


class ScanLog(models.Model):
    class Status(models.TextChoices):
        SAFE = "SAFE", "Safe"
        PHISHING = "PHISHING", "Phishing"
        UNKNOWN = "UNKNOWN", "Unknown"

    origin = models.URLField(max_length=500)
    status = models.CharField(max_length=20, choices=Status.choices)
    confidence = models.FloatField(
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    country = models.CharField(max_length=50, default="Unknown")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-timestamp",)
        indexes = (
            models.Index(fields=["-timestamp"], name="scanlog_recent_idx"),
            models.Index(
                fields=["status", "-timestamp"],
                name="scanlog_status_time_idx",
            ),
        )
        constraints = (
            models.CheckConstraint(
                condition=models.Q(confidence__gte=0, confidence__lte=100),
                name="scanlog_confidence_range",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["SAFE", "PHISHING", "UNKNOWN"]),
                name="scanlog_status_valid",
            ),
        )

    def __str__(self):
        return f"{self.origin} - {self.status}"
