from __future__ import annotations

from django.core.exceptions import PermissionDenied

from config.constants import OrgRole


def project_access(user, project, edit: bool = False):
    if not user.is_authenticated:
        raise PermissionDenied("Authentication required.")
    role = project.organization.role_for(user)
    if role is None:
        raise PermissionDenied("You are not a member of this organization.")
    if edit and role not in {OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER}:
        raise PermissionDenied("Your role cannot modify projects.")
    return role


def scan_access(user, scan, edit: bool = False):
    return project_access(user, scan.project, edit=edit)
