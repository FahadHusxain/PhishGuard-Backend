from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0007_alter_whitelistdomain_domain_and_more")]

    operations = [
        migrations.CreateModel(
            name="ThreatFeedSnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(max_length=64, unique=True)),
                ("retrieved_at", models.DateTimeField()),
                ("imported_at", models.DateTimeField(auto_now=True)),
                ("content_sha256", models.CharField(max_length=64)),
                ("indicator_count", models.PositiveIntegerField()),
            ],
            options={"ordering": ("source",)},
        ),
        migrations.CreateModel(
            name="ThreatIndicator",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(max_length=64)),
                ("url_sha256", models.CharField(max_length=64)),
                ("first_seen", models.DateTimeField()),
                ("last_seen", models.DateTimeField()),
                ("active", models.BooleanField(default=True)),
            ],
            options={
                "ordering": ("source", "url_sha256"),
                "indexes": [models.Index(fields=["url_sha256", "active"], name="threat_indicator_lookup_idx")],
                "constraints": [models.UniqueConstraint(fields=("source", "url_sha256"), name="threat_indicator_source_url_unique")],
            },
        ),
    ]
