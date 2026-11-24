from __future__ import annotations

from django.db import models

from config.constants import Priority


class RecommendationType(models.TextChoices):
    UPGRADE = "UPGRADE", "Secure version upgrade"
    MITIGATION = "MITIGATION", "Mitigation"
    PIN_VERSION = "PIN_VERSION", "Pin exact version"
    LICENSE_REVIEW = "LICENSE_REVIEW", "License review"
    RISK_REVIEW = "RISK_REVIEW", "Supply-chain risk review"
    AI_SUMMARY = "AI_SUMMARY", "AI remediation summary"


class Recommendation(models.Model):
    scan = models.ForeignKey("projects.Scan", on_delete=models.CASCADE, related_name="recommendations")
    vulnerability = models.ForeignKey(
        "vulnerability_scanner.Vulnerability", on_delete=models.CASCADE, related_name="recommendations",
        null=True, blank=True,
    )
    dependency = models.ForeignKey(
        "dependency_parser.ParsedDependency", on_delete=models.CASCADE, related_name="recommendations",
        null=True, blank=True,
    )
    type = models.CharField(max_length=30, choices=RecommendationType.choices)
    priority = models.CharField(max_length=20, choices=Priority.choices, default=Priority.MEDIUM)
    priority_rank = models.PositiveSmallIntegerField(default=2)
    title = models.CharField(max_length=300)
    explanation = models.TextField()
    recommended_version = models.CharField(max_length=120, blank=True)
    upgrade_steps = models.JSONField(default=list, blank=True)
    risks = models.TextField(blank=True)
    confidence = models.FloatField(default=1.0)
    source = models.CharField(max_length=30, default="RULE_ENGINE")
    raw = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-priority_rank", "-confidence", "title"]

    def __str__(self):
        return f"[{self.priority}] {self.title}"
