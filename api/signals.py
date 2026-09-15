"""Keep short-lived dashboard aggregates coherent after ordinary model writes."""

from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .dashboard import invalidate_dashboard_aggregates
from .models import ScanLog, WhitelistDomain


@receiver([post_save, post_delete], sender=ScanLog)
@receiver([post_save, post_delete], sender=WhitelistDomain)
def invalidate_dashboard_after_write(**_kwargs):
    # Delete immediately for autocommit writes, then again after an enclosing
    # transaction commits so a concurrent read cannot repopulate stale counts.
    invalidate_dashboard_aggregates()
    transaction.on_commit(invalidate_dashboard_aggregates)
