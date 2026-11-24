from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from django.db import models


class SBOM(models.Model):
    scan = models.OneToOneField("projects.Scan", on_delete=models.CASCADE, related_name="sbom")
    spec_version = models.CharField(max_length=20, default="1.5")
    serial_number = models.CharField(max_length=80)
    bom_ref = models.CharField(max_length=200)
    document = models.JSONField(default=dict)
    sha256 = models.CharField(max_length=64, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self):
        return f"SBOM {self.serial_number} ({self.spec_version})"

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.document, indent=indent, sort_keys=False)
