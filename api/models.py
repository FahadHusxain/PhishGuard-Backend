from django.db import models

class WhitelistDomain(models.Model):
    # db_index=True ka matlab hai fast searching
    domain = models.CharField(max_length=255, unique=True, db_index=True)

    def __str__(self):
        return self.domain