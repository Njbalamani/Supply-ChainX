from rest_framework.permissions import BasePermission

from config.constants import OrgRole


class IsOrganizationMember(BasePermission):
    message = "You must be a member of the owning organization."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        org_id = view.kwargs.get("organization_id")
        if org_id:
            from organizations.models import Organization

            return Organization.objects.filter(pk=org_id, memberships__user=request.user).exists()
        return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        organization = getattr(obj, "organization", None) or getattr(obj, "project", None).organization
        role = organization.role_for(request.user)
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return role is not None
        return role in {OrgRole.OWNER, OrgRole.ADMIN}
