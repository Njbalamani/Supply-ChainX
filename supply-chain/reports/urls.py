from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("scans/<int:scan_id>/report.pdf/", views.PDFReportView.as_view(), name="pdf"),
    path("scans/<int:scan_id>/vulnerabilities.csv/", views.VulnerabilityCSVView.as_view(), name="csv"),
    path("scans/<int:scan_id>/sbom.json/", views.SBOMDownloadView.as_view(), name="sbom"),
    path("scans/<int:scan_id>/risk.json/", views.RiskSummaryView.as_view(), name="risk"),
    path("scans/<int:scan_id>/graph.json/", views.GraphDataView.as_view(), name="graph"),
]
