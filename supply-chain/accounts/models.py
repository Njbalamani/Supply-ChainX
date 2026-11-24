from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models

from config.constants import Role


class User(AbstractUser):
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.DEVELOPER)
    title = models.CharField(max_length=120, blank=True)
    phone = models.CharField(max_length=40, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    last_activity = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["username"]

    @property
    def is_admin_role(self) -> bool:
        return self.role == Role.ADMIN or self.is_superuser

    @property
    def is_analyst_role(self) -> bool:
        return self.role in {Role.ANALYST, Role.ADMIN} or self.is_superuser

    def organizations(self):
        from organizations.models import Organization

        return Organization.objects.filter(memberships__user=self)
