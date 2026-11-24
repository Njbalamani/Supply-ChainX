from __future__ import annotations

from django.db import models

from config.constants import LicenseCategory


class LicenseRecord(models.Model):
    scan = models.ForeignKey("projects.Scan", on_delete=models.CASCADE, related_name="license_records")
    dependency = models.ForeignKey(
        "dependency_parser.ParsedDependency", on_delete=models.CASCADE, related_name="license_records",
        null=True, blank=True,
    )
    package_name = models.CharField(max_length=255)
    version = models.CharField(max_length=120, blank=True)
    license_id = models.CharField(max_length=200, blank=True)
    spdx_id = models.CharField(max_length=120, blank=True)
    category = models.CharField(
        max_length=30, choices=LicenseCategory.choices, default=LicenseCategory.UNKNOWN
    )
    compatible = models.BooleanField(default=True)
    requires_review = models.BooleanField(default=False)
    reason = models.TextField(blank=True)
    source = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ["package_name"]
        constraints = [
            models.UniqueConstraint(fields=["scan", "package_name", "version"], name="uniq_scan_license")
        ]

    def __str__(self):
        return f"{self.package_name}: {self.license_id or 'unknown'}"


class LicenseReport(models.Model):
    scan = models.OneToOneField("projects.Scan", on_delete=models.CASCADE, related_name="license_report")
    summary = models.JSONField(default=dict, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self):
        return f"License report for scan #{self.scan_id}"
