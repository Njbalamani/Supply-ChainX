from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.renderers import BrowsableAPIRenderer, JSONOpenAPIRenderer
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

from .api_views import DashboardSummaryAPIView
from .viewsets import (
    CVERecordViewSet,
    CurrentUserViewSet,
    DependencyEdgeViewSet,
    GraphMetricViewSet,
    IntelSourceStatusViewSet,
    LicenseRecordViewSet,
    OrganizationViewSet,
    ParsedDependencyViewSet,
    ProjectArchiveViewSet,
    ProjectViewSet,
    RecommendationViewSet,
    ReportViewSet,
    RiskSignalViewSet,
    SBOMViewSet,
    ScanViewSet,
    SecretFindingViewSet,
    VulnerabilityViewSet,
)

router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("projects", ProjectViewSet, basename="project")
router.register("archives", ProjectArchiveViewSet, basename="archive")
router.register("scans", ScanViewSet, basename="scan")
router.register("dependencies", ParsedDependencyViewSet, basename="dependency")
router.register("sboms", SBOMViewSet, basename="sbom")
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register("secret-findings", SecretFindingViewSet, basename="secret-finding")
router.register("recommendations", RecommendationViewSet, basename="recommendation")
router.register("licenses", LicenseRecordViewSet, basename="license")
router.register("reports", ReportViewSet, basename="report")
router.register("graph-metrics", GraphMetricViewSet, basename="graph-metric")
router.register("graph-edges", DependencyEdgeViewSet, basename="graph-edge")
router.register("risk-signals", RiskSignalViewSet, basename="risk-signal")
router.register("cve-records", CVERecordViewSet, basename="cve-record")
router.register("intel-sources", IntelSourceStatusViewSet, basename="intel-source")
router.register("me", CurrentUserViewSet, basename="me")

schema_view = get_schema_view(
    title="SupplyChainX API",
    description="AI-powered software supply chain security intelligence API.",
    version="1.0.0",
    public=False,
    renderer_classes=[JSONOpenAPIRenderer, BrowsableAPIRenderer],
)

urlpatterns = [
    path("auth/token/", obtain_auth_token, name="auth-token"),
    path("dashboard/summary/", DashboardSummaryAPIView.as_view(), name="dashboard-summary"),
    path("schema/", schema_view, name="schema"),
    path("", include(router.urls)),
]
