"""Shared enum-like choices used across SupplyChainX apps."""
from __future__ import annotations

from django.db import models


class Role(models.TextChoices):
    ADMIN = "ADMIN", "Administrator"
    DEVELOPER = "DEVELOPER", "Developer"
    ANALYST = "ANALYST", "Security Analyst"


class OrgRole(models.TextChoices):
    OWNER = "OWNER", "Owner"
    ADMIN = "ADMIN", "Admin"
    MEMBER = "MEMBER", "Member"
    VIEWER = "VIEWER", "Viewer"


class Ecosystem(models.TextChoices):
    PYTHON = "PYTHON", "Python"
    NODE = "NODE", "Node.js"
    JAVA = "JAVA", "Java / Maven"
    MULTI = "MULTI", "Multi-ecosystem"


class ScanStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    RUNNING = "RUNNING", "Running"
    COMPLETED = "COMPLETED", "Completed"
    FAILED = "FAILED", "Failed"


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Critical"
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"
    UNKNOWN = "UNKNOWN", "Unknown"


class IntelSource(models.TextChoices):
    OSV = "OSV", "OSV.dev"
    NVD = "NVD", "NVD CVE"
    PIP_AUDIT = "PIP_AUDIT", "pip-audit"
    GITLEAKS = "GITLEAKS", "Gitleaks"
    LOCAL = "LOCAL", "Local analysis"


class DependencyType(models.TextChoices):
    RUNTIME = "RUNTIME", "Runtime"
    DEVELOPMENT = "DEVELOPMENT", "Development"
    BUILD = "BUILD", "Build"
    TEST = "TEST", "Test"
    UNKNOWN = "UNKNOWN", "Unknown"


class LicenseCategory(models.TextChoices):
    PERMISSIVE = "PERMISSIVE", "Permissive"
    WEAK_COPYLEFT = "WEAK_COPYLEFT", "Weak copyleft"
    STRONG_COPYLEFT = "STRONG_COPYLEFT", "Strong copyleft"
    COMMERCIAL = "COMMERCIAL", "Commercial / proprietary"
    UNKNOWN = "UNKNOWN", "Unknown"


class Priority(models.TextChoices):
    CRITICAL = "CRITICAL", "Critical"
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"
