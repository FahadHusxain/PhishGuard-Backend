"""Delete scan logs that have exceeded the configured retention period."""

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from api.dashboard import invalidate_dashboard_aggregates
from api.models import ScanLog


class Command(BaseCommand):
    help = "Delete scan logs older than the configured retention period"

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            help="Override PHISHGUARD_SCAN_RETENTION_DAYS for this run",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many records would be deleted without deleting them",
        )

    def handle(self, *args, **options):
        days = options["days"]
        if days is None:
            days = settings.PHISHGUARD_SCAN_RETENTION_DAYS
        if days < 1:
            raise CommandError("Retention days must be at least 1")

        cutoff = timezone.now() - timedelta(days=days)
        expired_logs = ScanLog.objects.filter(timestamp__lt=cutoff)
        count = expired_logs.count()

        if options["dry_run"]:
            self.stdout.write(
                f"Would delete {count} scan log(s) older than {days} days"
            )
            return

        deleted_count, _ = expired_logs.delete()
        invalidate_dashboard_aggregates()
        self.stdout.write(
            self.style.SUCCESS(
                f"Deleted {deleted_count} scan log(s) older than {days} days"
            )
        )
