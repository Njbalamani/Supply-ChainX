from __future__ import annotations

from django.db import models

from config.constants import DependencyType, Ecosystem
from .purl import make_purl


class ParsedDependency(models.Model):
    scan = models.ForeignKey("projects.Scan", on_delete=models.CASCADE, related_name="dependencies")
    name = models.CharField(max_length=255, db_index=True)
    version = models.CharField(max_length=120, blank=True)
    ecosystem = models.CharField(max_length=20, choices=Ecosystem.choices, default=Ecosystem.PYTHON)
    source_file = models.CharField(max_length=500, blank=True)
    is_direct = models.BooleanField(default=True, db_index=True)
    dependency_type = models.CharField(
        max_length=20, choices=DependencyType.choices, default=DependencyType.RUNTIME
    )
    specifier = models.CharField(max_length=200, blank=True)
    parent_name = models.CharField(max_length=255, blank=True)
    license = models.CharField(max_length=200, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["ecosystem", "name", "version"]
        indexes = [models.Index(fields=["scan", "name"])]

    def __str__(self):
        return f"{self.name}=={self.version or '*'} ({self.ecosystem})"

    @property
    def purl(self) -> str:
        return make_purl(self.ecosystem, self.name, self.version, self.metadata)

    @property
    def is_vulnerable(self) -> bool:
        return self.vulnerabilities.exists()
