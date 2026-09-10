import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0005_scanlog_data_integrity"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="WhitelistAuditEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("domain", models.CharField(max_length=253)),
                (
                    "action",
                    models.CharField(
                        choices=[("ADDED", "Added"), ("PROMOTED", "Promoted")],
                        max_length=20,
                    ),
                ),
                ("actor_username", models.CharField(max_length=150)),
                (
                    "previous_rank",
                    models.PositiveIntegerField(blank=True, null=True),
                ),
                ("new_rank", models.PositiveIntegerField()),
                ("reason", models.CharField(max_length=500)),
                ("request_id", models.CharField(max_length=128)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-timestamp",),
                "indexes": [
                    models.Index(
                        fields=["domain", "-timestamp"],
                        name="whitelist_audit_lookup_idx",
                    )
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(("new_rank__gt", 0)),
                        name="whitelist_audit_rank_positive",
                    )
                ],
            },
        ),
    ]
