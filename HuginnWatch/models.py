from django.db import models
from django.contrib.auth.models import User

class Server(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField()
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"


class ScanResult(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now_add=True)
    ports = models.TextField()
    raw_output = models.TextField()
    open_ports_count = models.IntegerField(default=0)
    vulnerability_count = models.IntegerField(default=0)
    vulnerabilities_json = models.JSONField(null=True, blank=True)  # structured CVEs

    def __str__(self):
        return f"Scan for {self.server.name} on {self.scan_date}"
