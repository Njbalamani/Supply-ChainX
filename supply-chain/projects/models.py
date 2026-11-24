from __future__ import annotations

import hashlib

from django.conf import settings
from django.db import models
from django.utils.text import slugify

from config.constants import Ecosystem, ScanStatus
from .storage import archive_upload_path


class Project(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="projects"
    )
    name = models.CharField(max_length=180)
    slug = models.SlugField(max_length=220, blank=True)
    ecosystem = models.CharField(max_length=20, choices=Ecosystem.choices, default=Ecosystem.PYTHON)
    description = models.TextField(blank=True)
    repository_url = models.URLField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_projects"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "name"], name="uniq_org_project_name")]
        ordering = ["name"]

    def __str__(self):
        return f"{self.organization.name}/{self.name}"

    def save(self, *args, **kwargs):
        if not self.slug:
            base = f"{self.organization_id or 'org'}-{self.name}"
            self.slug = slugify(base)[:220] or f"project-{self.pk or uuid_hex()}"
        super().save(*args, **kwargs)

    @property
    def latest_scan(self):
        return self.scans.order_by("-created_at").first()

    def scan_count(self):
        return self.scans.count()


def uuid_hex():
    import uuid

    return uuid.uuid4().hex


class ProjectArchive(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="archives")
    file = models.FileField(upload_to=archive_upload_path)
    original_filename = models.CharField(max_length=255)
    size_bytes = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64, db_index=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="uploaded_archives"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"{self.original_filename} ({self.sha256[:12]})"

    def compute_sha256(self) -> str:
        digest = hashlib.sha256()
        self.file.open("rb")
        try:
            for chunk in self.file.chunks():
                digest.update(chunk)
        finally:
            self.file.close()
        return digest.hexdigest()


class Scan(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="scans")
    archive = models.ForeignKey(
        ProjectArchive, on_delete=models.SET_NULL, null=True, blank=True, related_name="scans"
    )
    status = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING, db_index=True)
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="triggered_scans"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    summary = models.JSONField(default=dict, blank=True)
    sources = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    health_score = models.PositiveSmallIntegerField(default=100)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["project", "status"])]

    def __str__(self):
        return f"Scan #{self.pk} - {self.project.name} ({self.status})"

    @property
    def is_finished(self) -> bool:
        return self.status in {ScanStatus.COMPLETED, ScanStatus.FAILED}

    @property
    def duration_seconds(self):
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at).total_seconds(), 2)
        return None
