from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils.text import slugify

from config.constants import OrgRole


class Organization(models.Model):
    name = models.CharField(max_length=180, unique=True)
    slug = models.SlugField(max_length=200, unique=True, blank=True)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="owned_organizations")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)[:200] or f"org-{self.pk or 'new'}"
        super().save(*args, **kwargs)

    def role_for(self, user) -> str | None:
        if not user or not user.is_authenticated:
            return None
        if user.is_superuser:
            return OrgRole.OWNER
        membership = self.memberships.filter(user=user).first()
        return membership.role if membership else None

    def can_view(self, user) -> bool:
        return self.role_for(user) is not None

    def can_edit(self, user) -> bool:
        return self.role_for(user) in {OrgRole.OWNER, OrgRole.ADMIN}


class OrganizationMember(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=20, choices=OrgRole.choices, default=OrgRole.MEMBER)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "user"], name="uniq_org_member")]
        ordering = ["organization", "user__username"]

    def __str__(self):
        return f"{self.user.username} @ {self.organization.name} ({self.role})"
