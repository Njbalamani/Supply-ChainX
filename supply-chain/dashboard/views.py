from __future__ import annotations

import json
from collections import Counter
from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Avg, Count
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.views.generic import TemplateView

from config.constants import Ecosystem, ScanStatus, Severity
from dependency_parser.models import ParsedDependency
from projects.models import Project, Scan
from vulnerability_scanner.models import Vulnerability


def _scoped_projects(user):
    if user.is_superuser:
        return Project.objects.all()
    return Project.objects.filter(organization__memberships__user=user).distinct()


def ecosystem_labels(key: str) -> str:
    return dict(Ecosystem.choices).get(key, key)


def home(request):
    if request.user.is_authenticated:
        return redirect(reverse("dashboard:home"))
    return redirect(reverse("accounts:login"))


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        projects = _scoped_projects(self.request.user)
        project_ids = list(projects.values_list("id", flat=True))
        scans = Scan.objects.filter(project_id__in=project_ids)
        completed = scans.filter(status=ScanStatus.COMPLETED)

        dependency_count = ParsedDependency.objects.filter(scan__project_id__in=project_ids).count()
        vulnerabilities = Vulnerability.objects.filter(scan__project_id__in=project_ids)
        severity_counts = {level: vulnerabilities.filter(severity=level).count() for level in [s[0] for s in Severity.choices]}
        ecosystem_counts = dict(
            ParsedDependency.objects.filter(scan__project_id__in=project_ids)
            .values("ecosystem")
            .annotate(total=Count("id"))
            .values_list("ecosystem", "total")
        )
        ecosystem_counts = {ecosystem_labels(label): count for label, count in ecosystem_counts.items()}

        today = timezone.now().date()
        activity = []
        for offset in range(13, -1, -1):
            day = today - timedelta(days=offset)
            count = scans.filter(created_at__date=day).count()
            activity.append({"date": day.isoformat(), "count": count})

        avg_health = completed.aggregate(avg=Avg("health_score"))["avg"] or 0
        context.update(
            {
                "total_projects": projects.count(),
                "total_scans": scans.count(),
                "completed_scans": completed.count(),
                "running_scans": scans.filter(status=ScanStatus.RUNNING).count(),
                "failed_scans": scans.filter(status=ScanStatus.FAILED).count(),
                "total_dependencies": dependency_count,
                "vulnerable_packages": vulnerabilities.values("package_name").distinct().count(),
                "critical_cves": vulnerabilities.filter(severity=Severity.CRITICAL).exclude(cve_id="").count(),
                "health_score": round(avg_health),
                "risk_score": round(completed.aggregate(avg=Avg("risk_score"))["avg"] or 0),
                "severity_counts": severity_counts,
                "severity_labels": [label for _, label in Severity.choices],
                "ecosystem_counts": ecosystem_counts,
                "activity": activity,
                "recent_scans": scans.select_related("project", "project__organization")[:10],
                "top_projects": projects.annotate(scan_total=Count("scans")).order_by("-scan_total")[:6],
            }
        )
        context["severity_chart"] = json.dumps(
            {
                "type": "doughnut",
                "data": {
                    "labels": context["severity_labels"],
                    "datasets": [{
                        "data": list(context["severity_counts"].values()),
                        "backgroundColor": ["#ff5d6c", "#ffa63d", "#c9a227", "#36d399", "#5aa9ff"],
                        "borderWidth": 0,
                    }],
                },
            }
        )
        context["activity_chart"] = json.dumps(
            {
                "type": "line",
                "data": {
                    "labels": [a["date"][5:] for a in activity],
                    "datasets": [{
                        "label": "Scans",
                        "data": [a["count"] for a in activity],
                        "borderColor": "#c9a227",
                        "backgroundColor": "rgba(201,162,39,.12)",
                        "fill": True,
                        "tension": 0.4,
                        "pointRadius": 2,
                    }],
                },
            }
        )
        context["ecosystem_chart"] = json.dumps(
            {
                "type": "bar",
                "data": {
                    "labels": list(ecosystem_counts.keys()) or ["No data"],
                    "datasets": [{
                        "label": "Dependencies",
                        "data": list(ecosystem_counts.values()) or [0],
                        "backgroundColor": ["#c9a227", "#5aa9ff", "#a78bfa", "#36d399"],
                        "borderRadius": 6,
                    }],
                },
            }
        )
        return context
