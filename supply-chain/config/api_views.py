from __future__ import annotations

from django.db.models import Avg, Count
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.views import _scoped_projects, ecosystem_labels
from dependency_parser.models import ParsedDependency
from projects.models import Project, Scan
from vulnerability_scanner.models import Vulnerability


class DashboardSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        projects = _scoped_projects(request.user)
        scans = Scan.objects.filter(project_id__in=projects.values_list("id", flat=True))
        completed = scans.filter(status="COMPLETED")
        vulnerabilities = Vulnerability.objects.filter(scan__project_id__in=projects.values_list("id", flat=True))
        ecosystems = dict(
            ParsedDependency.objects.filter(scan__project_id__in=projects.values_list("id", flat=True))
            .values("ecosystem")
            .annotate(total=Count("id"))
            .values_list("ecosystem", "total")
        )
        return Response(
            {
                "projects": projects.count(),
                "scans": scans.count(),
                "completed_scans": completed.count(),
                "dependencies": ParsedDependency.objects.filter(
                    scan__project_id__in=projects.values_list("id", flat=True)
                ).count(),
                "vulnerable_packages": vulnerabilities.values("package_name").distinct().count(),
                "critical_cves": vulnerabilities.filter(severity="CRITICAL").exclude(cve_id="").count(),
                "average_health_score": round(completed.aggregate(avg=Avg("health_score"))["avg"] or 0),
                "ecosystems": {ecosystem_labels(k): v for k, v in ecosystems.items()},
            }
        )
