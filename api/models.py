from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.functions import Lower

from .domains import normalize_hostname


class WhitelistDomain(models.Model):
    domain = models.CharField(max_length=253, unique=True, db_index=True)
    rank = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ("rank", "domain")
        constraints = (
            models.CheckConstraint(
                condition=models.Q(rank__gte=0),
                name="whitelist_rank_nonnegative",
            ),
            models.UniqueConstraint(
                Lower("domain"),
                name="whitelist_domain_case_insensitive_unique",
            ),
        )

    def __str__(self):
        return self.domain

    def save(self, *args, **kwargs):
        self.domain = normalize_hostname(self.domain)
        return super().save(*args, **kwargs)

    def clean(self):
        super().clean()
        self.domain = normalize_hostname(self.domain)


class WhitelistAuditEvent(models.Model):
    class Action(models.TextChoices):
        ADDED = "ADDED", "Added"
        PROMOTED = "PROMOTED", "Promoted"

    domain = models.CharField(max_length=253)
    action = models.CharField(max_length=20, choices=Action.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    actor_username = models.CharField(max_length=150)
    previous_rank = models.PositiveIntegerField(null=True, blank=True)
    new_rank = models.PositiveIntegerField()
    reason = models.CharField(max_length=500)
    request_id = models.CharField(max_length=128)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-timestamp",)
        indexes = (
            models.Index(
                fields=["domain", "-timestamp"],
                name="whitelist_audit_lookup_idx",
            ),
        )
        constraints = (
            models.CheckConstraint(
                condition=models.Q(new_rank__gt=0),
                name="whitelist_audit_rank_positive",
            ),
        )

    def __str__(self):
        return f"{self.domain} - {self.action}"


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
