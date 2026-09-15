"""Exit unsuccessfully when enabled threat intelligence is not ready."""

from django.core.management.base import BaseCommand, CommandError

from api.threat_intelligence import threat_feed_health


class Command(BaseCommand):
    help = "Check whether at least one enabled threat feed is fresh and populated."

    def handle(self, *args, **options):
        health = threat_feed_health()
        if health.status == "disabled":
            self.stdout.write("Threat intelligence is disabled.")
            return
        if health.status != "fresh":
            raise CommandError(f"Threat intelligence is {health.status}.")
        self.stdout.write(
            self.style.SUCCESS(
                f"Threat intelligence is fresh: {health.source_count} source(s), "
                f"{health.active_indicator_count} active indicator(s)."
            )
        )
