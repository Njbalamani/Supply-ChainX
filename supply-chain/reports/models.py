from __future__ import annotations

from django.conf import settings
from django.db import models


class Report(models.Model):
    class ReportType(models.TextChoices):
        PDF = "PDF", "PDF report"
        SBOM_JSON = "SBOM_JSON", "SBOM JSON"
        VULNERABILITY_CSV = "VULNERABILITY_CSV", "Vulnerability CSV"
        RISK_SUMMARY = "RISK_SUMMARY", "Risk summary"

    scan = models.ForeignKey("projects.Scan", on_delete=models.CASCADE, related_name="reports")
    report_type = models.CharField(max_length=30, choices=ReportType.choices)
    file = models.FileField(upload_to="reports/", blank=True)
    title = models.CharField(max_length=200, blank=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="generated_reports"
    )
    generated_at = models.DateTimeField(auto_now_add=True)
    checksum = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self):
        return f"{self.get_report_type_display()} - scan #{self.scan_id}"
