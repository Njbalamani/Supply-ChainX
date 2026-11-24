from __future__ import annotations

from django.db import models

from config.constants import IntelSource, Severity


class IntelSourceStatus(models.Model):
    name = models.CharField(max_length=40, choices=IntelSource.choices, unique=True)
    status = models.CharField(max_length=20, default="UNKNOWN")
    message = models.TextField(blank=True)
    last_attempt = models.DateTimeField(null=True, blank=True)
    last_success = models.DateTimeField(null=True, blank=True)
    request_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name}: {self.status}"


class CVERecord(models.Model):
    cve_id = models.CharField(max_length=40, unique=True, db_index=True)
    source = models.CharField(max_length=20, choices=IntelSource.choices, default=IntelSource.NVD)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.UNKNOWN)
    cvss_score = models.FloatField(null=True, blank=True)
    vector_string = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    published = models.DateTimeField(null=True, blank=True)
    last_modified = models.DateTimeField(null=True, blank=True)
    references = models.JSONField(default=list, blank=True)
    configurations = models.JSONField(default=list, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-cvss_score", "cve_id"]

    def __str__(self):
        return f"{self.cve_id} ({self.severity})"
