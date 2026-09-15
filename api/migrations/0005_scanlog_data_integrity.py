from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


def normalize_existing_rows(apps, schema_editor):
    scan_log = apps.get_model("api", "ScanLog")
    whitelist_domain = apps.get_model("api", "WhitelistDomain")

    scan_log.objects.exclude(status__in=["SAFE", "PHISHING", "UNKNOWN"]).update(
        status="UNKNOWN"
    )
    scan_log.objects.filter(confidence__lt=0).update(confidence=0)
    scan_log.objects.filter(confidence__gt=100).update(confidence=100)
    whitelist_domain.objects.filter(rank__lt=0).update(rank=0)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_whitelistdomain_rank"),
    ]

    operations = [
        migrations.RenameField(
            model_name="scanlog",
            old_name="url",
            new_name="origin",
        ),
        migrations.RunPython(normalize_existing_rows, migrations.RunPython.noop),
        migrations.AlterModelOptions(
            name="scanlog",
            options={"ordering": ("-timestamp",)},
        ),
        migrations.AlterModelOptions(
            name="whitelistdomain",
            options={"ordering": ("rank", "domain")},
        ),
        migrations.AlterField(
            model_name="scanlog",
            name="confidence",
            field=models.FloatField(
                validators=[MinValueValidator(0), MaxValueValidator(100)]
            ),
        ),
        migrations.AlterField(
            model_name="scanlog",
            name="status",
            field=models.CharField(
                choices=[
                    ("SAFE", "Safe"),
                    ("PHISHING", "Phishing"),
                    ("UNKNOWN", "Unknown"),
                ],
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name="whitelistdomain",
            name="rank",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddIndex(
            model_name="scanlog",
            index=models.Index(fields=["-timestamp"], name="scanlog_recent_idx"),
        ),
        migrations.AddIndex(
            model_name="scanlog",
            index=models.Index(
                fields=["status", "-timestamp"],
                name="scanlog_status_time_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="scanlog",
            constraint=models.CheckConstraint(
                condition=models.Q(confidence__gte=0, confidence__lte=100),
                name="scanlog_confidence_range",
            ),
        ),
        migrations.AddConstraint(
            model_name="scanlog",
            constraint=models.CheckConstraint(
                condition=models.Q(status__in=["SAFE", "PHISHING", "UNKNOWN"]),
                name="scanlog_status_valid",
            ),
        ),
        migrations.AddConstraint(
            model_name="whitelistdomain",
            constraint=models.CheckConstraint(
                condition=models.Q(rank__gte=0),
                name="whitelist_rank_nonnegative",
            ),
        ),
    ]
