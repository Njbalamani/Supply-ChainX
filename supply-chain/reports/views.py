from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View

from config.constants import ScanStatus
from projects.models import Scan
from projects.permissions import scan_access
from .models import Report
from .services import create_report, risk_summary_dict, vulnerability_csv_bytes


class ReportDownloadBase(LoginRequiredMixin, View):
    report_type = None

    def dispatch(self, request, *args, **kwargs):
        self.scan = get_object_or_404(Scan.objects.select_related("project"), pk=kwargs["scan_id"])
        scan_access(request.user, self.scan)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        report = create_report(self.scan, self.report_type, user=request.user)
        return FileResponse(
            report.file.open("rb"),
            as_attachment=True,
            filename=report.file.name.split("/")[-1],
            content_type="application/octet-stream",
        )


class PDFReportView(ReportDownloadBase):
    report_type = Report.ReportType.PDF


class VulnerabilityCSVView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        scan = get_object_or_404(Scan.objects.select_related("project"), pk=kwargs["scan_id"])
        scan_access(request.user, scan)
        data = vulnerability_csv_bytes(scan)
        response = HttpResponse(data, content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="supplychainx-vulnerabilities-{scan.pk}.csv"'
        create_report(scan, Report.ReportType.VULNERABILITY_CSV, user=request.user, content=data,
                      filename=f"supplychainx-vulnerabilities-{scan.pk}.csv")
        return response


class SBOMDownloadView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        scan = get_object_or_404(Scan.objects.select_related("project"), pk=kwargs["scan_id"])
        scan_access(request.user, scan)
        sbom = getattr(scan, "sbom", None)
        if not sbom:
            return HttpResponse("SBOM is not available for this scan.", status=404, content_type="text/plain")
        data = sbom.to_json().encode("utf-8")
        response = HttpResponse(data, content_type="application/json")
        response["Content-Disposition"] = f'attachment; filename="supplychainx-sbom-{scan.pk}.json"'
        create_report(scan, Report.ReportType.SBOM_JSON, user=request.user, content=data,
                      filename=f"supplychainx-sbom-{scan.pk}.json")
        return response


class RiskSummaryView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        scan = get_object_or_404(Scan.objects.select_related("project"), pk=kwargs["scan_id"])
        scan_access(request.user, scan)
        return JsonResponse(risk_summary_dict(scan), json_dumps_params={"indent": 2})


class GraphDataView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        from dependency_graph.service import graph_payload

        scan = get_object_or_404(Scan.objects.select_related("project"), pk=kwargs["scan_id"])
        scan_access(request.user, scan)
        return JsonResponse(graph_payload(scan))
