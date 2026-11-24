from rest_framework import serializers

from accounts.models import User
from ai_recommendations.models import Recommendation
from cve_intelligence.models import CVERecord, IntelSourceStatus
from dependency_graph.models import DependencyEdge, GraphMetric, RiskSignal
from dependency_parser.models import ParsedDependency
from license_compliance.models import LicenseRecord
from organizations.models import Organization, OrganizationMember
from projects.models import Project, ProjectArchive, Scan
from reports.models import Report
from sbom_generator.models import SBOM
from vulnerability_scanner.models import SecretFinding, Vulnerability


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "role", "title", "is_staff")


class OrganizationSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ("id", "name", "slug", "description", "owner", "member_count", "created_at")
        read_only_fields = ("slug", "owner")

    def get_member_count(self, obj):
        return obj.memberships.count()

    def create(self, validated_data):
        validated_data["owner"] = self.context["request"].user
        organization = super().create(validated_data)
        OrganizationMember.objects.create(organization=organization, user=validated_data["owner"], role="OWNER")
        return organization


class ProjectSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    latest_scan_id = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = (
            "id", "organization", "organization_name", "name", "slug", "ecosystem", "description",
            "repository_url", "created_by", "created_at", "updated_at", "latest_scan_id",
        )
        read_only_fields = ("slug", "created_by")

    def get_latest_scan_id(self, obj):
        scan = obj.latest_scan
        return scan.pk if scan else None

    def validate_organization(self, value):
        request = self.context.get("request")
        if request and not request.user.is_superuser and not value.can_view(request.user):
            raise serializers.ValidationError("You are not a member of this organization.")
        return value

    def create(self, validated_data):
        validated_data["created_by"] = self.context["request"].user
        return super().create(validated_data)


class ProjectArchiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectArchive
        fields = ("id", "project", "original_filename", "size_bytes", "sha256", "uploaded_at")
        read_only_fields = ("size_bytes", "sha256", "uploaded_at")


class ScanSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)
    duration_seconds = serializers.FloatField(read_only=True)

    class Meta:
        model = Scan
        fields = (
            "id", "project", "project_name", "archive", "status", "triggered_by", "created_at",
            "started_at", "finished_at", "duration_seconds", "error_message", "summary", "sources",
            "risk_score", "health_score",
        )
        read_only_fields = ("triggered_by", "status", "started_at", "finished_at", "error_message")

    def create(self, validated_data):
        validated_data["triggered_by"] = self.context["request"].user
        return super().create(validated_data)


class ParsedDependencySerializer(serializers.ModelSerializer):
    purl = serializers.CharField(read_only=True)
    is_vulnerable = serializers.BooleanField(read_only=True)

    class Meta:
        model = ParsedDependency
        fields = (
            "id", "scan", "name", "version", "ecosystem", "source_file", "is_direct",
            "dependency_type", "specifier", "parent_name", "license", "metadata", "purl",
            "is_vulnerable", "created_at",
        )


class SBOMSerializer(serializers.ModelSerializer):
    class Meta:
        model = SBOM
        fields = ("id", "scan", "spec_version", "serial_number", "bom_ref", "sha256", "generated_at", "document")


class VulnerabilitySerializer(serializers.ModelSerializer):
    cve_or_id = serializers.CharField(read_only=True)
    has_known_fix = serializers.BooleanField(read_only=True)

    class Meta:
        model = Vulnerability
        fields = (
            "id", "scan", "dependency", "vuln_id", "cve_id", "cve_or_id", "package_name",
            "package_version", "ecosystem", "is_direct", "severity", "cvss_score", "cvss_vector",
            "summary", "description", "aliases", "sources", "source", "source_url", "affected_range",
            "fixed_versions", "references", "published", "modified", "enrichment_notes", "has_known_fix",
        )


class SecretFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecretFinding
        fields = "__all__"


class RecommendationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Recommendation
        fields = "__all__"


class LicenseRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseRecord
        fields = "__all__"


class ReportSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = "__all__"
        read_only_fields = ("checksum", "generated_at")

    def get_download_url(self, obj):
        return obj.file.url if obj.file else ""


class GraphMetricSerializer(serializers.ModelSerializer):
    class Meta:
        model = GraphMetric
        fields = "__all__"


class DependencyEdgeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DependencyEdge
        fields = "__all__"


class RiskSignalSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskSignal
        fields = "__all__"


class CVERecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = CVERecord
        fields = "__all__"


class IntelSourceStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelSourceStatus
        fields = "__all__"
