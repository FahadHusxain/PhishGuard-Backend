from django.db import models

class WhitelistDomain(models.Model):
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    rank = models.IntegerField(default=0)  # <--- Ye line missing thi
    
    def __str__(self):
        return self.domain
    # ... purana code ...

class ScanLog(models.Model):
    url = models.URLField(max_length=500)
    status = models.CharField(max_length=20)
    confidence = models.FloatField()
    country = models.CharField(max_length=50, default="Unknown")  # <--- New Field
    ip_address = models.GenericIPAddressField(null=True, blank=True) # <--- New Field
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.status}"