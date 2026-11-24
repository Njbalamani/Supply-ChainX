from __future__ import annotations

from django.db import models


class DependencyEdge(models.Model):
    scan = models.ForeignKey("projects.Scan", on_delete=models.CASCADE, related_name="edges")
    source = models.CharField(max_length=255)
    target = models.CharField(max_length=255)
    edge_type = models.CharField(max_length=20, default="DIRECT")
    source_file = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["source", "target"]
        constraints = [
            models.UniqueConstraint(
                fields=["scan", "source", "target", "edge_type"], name="uniq_scan_edge"
            )
        ]

    def __str__(self):
        return f"{self.source} -> {self.target}"


class RiskSignal(models.Model):
    scan = models.ForeignKey("projects.Scan", on_delete=models.CASCADE, related_name="risk_signals")
    dependency = models.ForeignKey(
        "dependency_parser.ParsedDependency", on_delete=models.CASCADE, related_name="risk_signals",
        null=True, blank=True,
    )
    signal_type = models.CharField(max_length=60, db_index=True)
    severity = models.CharField(max_length=20, default="MEDIUM")
    description = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.signal_type}: {self.description[:60]}"


class GraphMetric(models.Model):
    scan = models.OneToOneField("projects.Scan", on_delete=models.CASCADE, related_name="graph_metrics")
    node_count = models.PositiveIntegerField(default=0)
    edge_count = models.PositiveIntegerField(default=0)
    vulnerable_node_count = models.PositiveIntegerField(default=0)
    direct_count = models.PositiveIntegerField(default=0)
    transitive_count = models.PositiveIntegerField(default=0)
    max_depth = models.PositiveIntegerField(default=0)
    vulnerable_paths = models.JSONField(default=list, blank=True)
    concentration = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    computed_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-computed_at"]

    def __str__(self):
        return f"Graph metrics for scan #{self.scan_id}"
