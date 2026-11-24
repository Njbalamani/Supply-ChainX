from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import serializers

from ai_recommendations.models import Recommendation
from cve_intelligence.models import CVERecord, IntelSourceStatus
from dependency_graph.models import DependencyEdge, GraphMetric, RiskSignal
from dependency_parser.archive import ArchiveValidationError
from dependency_parser.models import ParsedDependency
from license_compliance.models import LicenseRecord
from organizations.api_permissions import IsOrganizationMember
from organizations.models import Organization
from projects.models import Project, ProjectArchive, Scan
from projects.services import dispatch_scan, save_project_archive
from reports.models import Report
from reports.services import risk_summary_dict
from sbom_generator.models import SBOM
from vulnerability_scanner.models import SecretFinding, Vulnerability

from .serializers import (
    CVERecordSerializer,
    DependencyEdgeSerializer,
    GraphMetricSerializer,
    IntelSourceStatusSerializer,
    LicenseRecordSerializer,
    OrganizationSerializer,
    ParsedDependencySerializer,
    ProjectArchiveSerializer,
    ProjectSerializer,
    RecommendationSerializer,
    ReportSerializer,
    RiskSignalSerializer,
    SBOMSerializer,
    ScanSerializer,
    SecretFindingSerializer,
    UserSerializer,
    VulnerabilitySerializer,
)


def _scoped_project_ids(user):
    from dashboard.views import _scoped_projects

    return _scoped_projects(user).values_list("id", flat=True)


class ScopedViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def scoped_project_ids(self):
        return _scoped_project_ids(self.request.user)


class OrganizationViewSet(viewsets.ModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Organization.objects.all()
        return Organization.objects.filter(memberships__user=self.request.user).distinct()


class ProjectViewSet(ScopedViewSet):
    serializer_class = ProjectSerializer

    def get_queryset(self):
        return Project.objects.filter(id__in=_scoped_project_ids(self.request.user)).select_related("organization")

    @action(detail=True, methods=["post"], parser_classes=[MultiPartParser, FormParser], url_path="upload")
    def upload(self, request, pk=None):
        project = self.get_object()
        if not project.organization.can_edit(request.user):
            raise PermissionDenied("Insufficient organization role.")
        archive_file = request.FILES.get("archive")
        if not archive_file:
            return Response({"detail": "archive file is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not archive_file.name.lower().endswith(".zip"):
            return Response({"detail": "Only .zip archives are accepted."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            archive = save_project_archive(project, archive_file, request.user)
            scan = Scan.objects.create(project=project, archive=archive, triggered_by=request.user)
            queue_info = dispatch_scan(scan)
            scan.summary = {"queue": queue_info}
            scan.save(update_fields=["summary"])
        except ArchiveValidationError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(ScanSerializer(scan, context={"request": request}).data, status=status.HTTP_201_CREATED)


class ProjectArchiveViewSet(ScopedViewSet):
    serializer_class = ProjectArchiveSerializer

    def get_queryset(self):
        return ProjectArchive.objects.filter(project_id__in=_scoped_project_ids(self.request.user))


class ScanViewSet(ScopedViewSet):
    serializer_class = ScanSerializer

    def get_queryset(self):
        return Scan.objects.filter(project_id__in=_scoped_project_ids(self.request.user)).select_related("project")

    @action(detail=True, methods=["post"], url_path="queue")
    def queue(self, request, pk=None):
        scan = self.get_object()
        if scan.status not in {"PENDING", "FAILED"}:
            return Response({"detail": "Scan is already running or completed."}, status=status.HTTP_409_CONFLICT)
        scan.status = "PENDING"
        scan.error_message = ""
        scan.save(update_fields=["status", "error_message"])
        info = dispatch_scan(scan)
        return Response({"id": scan.pk, "queue": info}, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["get"], url_path="summary")
    def summary(self, request, pk=None):
        return Response(risk_summary_dict(self.get_object()))


class ParsedDependencyViewSet(ScopedViewSet):
    serializer_class = ParsedDependencySerializer

    def get_queryset(self):
        return ParsedDependency.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class SBOMViewSet(ScopedViewSet):
    serializer_class = SBOMSerializer

    def get_queryset(self):
        return SBOM.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class VulnerabilityViewSet(ScopedViewSet):
    serializer_class = VulnerabilitySerializer

    def get_queryset(self):
        return Vulnerability.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class SecretFindingViewSet(ScopedViewSet):
    serializer_class = SecretFindingSerializer

    def get_queryset(self):
        return SecretFinding.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class RecommendationViewSet(ScopedViewSet):
    serializer_class = RecommendationSerializer

    def get_queryset(self):
        return Recommendation.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class LicenseRecordViewSet(ScopedViewSet):
    serializer_class = LicenseRecordSerializer

    def get_queryset(self):
        return LicenseRecord.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class ReportViewSet(ScopedViewSet):
    serializer_class = ReportSerializer

    def get_queryset(self):
        return Report.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class GraphMetricViewSet(ScopedViewSet):
    serializer_class = GraphMetricSerializer

    def get_queryset(self):
        return GraphMetric.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class DependencyEdgeViewSet(ScopedViewSet):
    serializer_class = DependencyEdgeSerializer

    def get_queryset(self):
        return DependencyEdge.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class RiskSignalViewSet(ScopedViewSet):
    serializer_class = RiskSignalSerializer

    def get_queryset(self):
        return RiskSignal.objects.filter(scan__project_id__in=_scoped_project_ids(self.request.user))


class CVERecordViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CVERecordSerializer
    permission_classes = [IsAuthenticated]
    queryset = CVERecord.objects.all()


class IntelSourceStatusViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = IntelSourceStatusSerializer
    permission_classes = [IsAuthenticated]
    queryset = IntelSourceStatus.objects.all()


class CurrentUserViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        return Response(UserSerializer(request.user, context={"request": request}).data)
