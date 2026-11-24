"""Reusable organization-scoped authorization helpers."""
from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

from config.constants import OrgRole
from organizations.models import Organization


def get_org_or_404(organization_id, user):
    org = get_object_or_404(Organization, pk=organization_id)
    if not org.can_view(user):
        raise PermissionDenied("You are not a member of this organization.")
    return org


def require_org_role(user, organization, allowed_roles):
    role = organization.role_for(user)
    if role not in set(allowed_roles):
        raise PermissionDenied("Insufficient role for this operation.")
    return role


class OrganizationScopedMixin:
    """MVT mixin that resolves an organization and enforces membership."""

    org_lookup_kwarg = "organization_id"

    def dispatch(self, request, *args, **kwargs):
        self.organization = get_org_or_404(kwargs.get(self.org_lookup_kwarg), request.user)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organization"] = self.organization
        return context
