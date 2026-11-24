from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views import View
from django.views.generic import CreateView, DetailView, ListView

from config.constants import ScanStatus
from organizations.models import Organization
from .forms import ProjectForm, SourceArchiveForm
from .models import Project, Scan
from .permissions import project_access, scan_access
from .services import dispatch_scan, save_project_archive
from dependency_parser.archive import ArchiveValidationError


class ProjectListView(LoginRequiredMixin, ListView):
    model = Project
    template_name = "projects/list.html"
    context_object_name = "projects"

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Project.objects.select_related("organization").all()
        return Project.objects.select_related("organization").filter(
            organization__memberships__user=self.request.user
        ).distinct()


class ProjectCreateView(LoginRequiredMixin, CreateView):
    form_class = ProjectForm
    template_name = "projects/create.html"

    def dispatch(self, request, *args, **kwargs):
        self.organization = get_object_or_404(Organization, pk=kwargs["organization_id"])
        if not self.organization.can_edit(request.user):
            raise PermissionDenied("You cannot create projects in this organization.")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.instance.organization = self.organization
        form.instance.created_by = self.request.user
        response = super().form_valid(form)
        messages.success(self.request, "Project registered.")
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organization"] = self.organization
        return context

    def get_success_url(self):
        return reverse("projects:detail", kwargs={"pk": self.object.pk})


class ProjectDetailView(LoginRequiredMixin, DetailView):
    model = Project
    template_name = "projects/detail.html"
    context_object_name = "project"

    def get_object(self, queryset=None):
        project = super().get_object(queryset)
        project_access(self.request.user, project)
        return project

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["scans"] = self.object.scans.select_related("archive", "triggered_by")[:25]
        context["upload_form"] = SourceArchiveForm()
        context["can_scan"] = self.object.organization.can_edit(self.request.user)
        return context


class ProjectUploadView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        self.project = get_object_or_404(Project, pk=kwargs["pk"])
        project_access(self.request.user, self.project, edit=True)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        form = SourceArchiveForm(request.POST, request.FILES)
        if not form.is_valid():
            messages.error(request, " ".join(form.errors.as_text().splitlines()))
            return redirect("projects:detail", pk=self.project.pk)
        try:
            archive = save_project_archive(self.project, form.cleaned_data["archive"], request.user)
            scan = Scan.objects.create(
                project=self.project,
                archive=archive,
                triggered_by=request.user,
                status=ScanStatus.PENDING,
            )
            queue_info = dispatch_scan(scan)
            scan.summary = {"queue": queue_info}
            scan.save(update_fields=["summary"])
            messages.success(request, f"Scan #{scan.pk} queued ({queue_info['mode']}).")
        except ArchiveValidationError as exc:
            messages.error(request, f"Archive rejected: {exc}")
        except Exception as exc:
            messages.error(request, f"Scan could not be started: {exc}")
        return redirect("projects:detail", pk=self.project.pk)


class ScanStatusView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        scan = get_object_or_404(Scan.objects.select_related("project"), pk=kwargs["scan_id"])
        scan_access(request.user, scan)
        return JsonResponse(
            {
                "id": scan.pk,
                "status": scan.status,
                "risk_score": scan.risk_score,
                "health_score": scan.health_score,
                "summary": scan.summary,
                "error_message": scan.error_message,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            }
        )


class ScanDetailView(LoginRequiredMixin, DetailView):
    model = Scan
    template_name = "scans/detail.html"
    context_object_name = "scan"
    pk_url_kwarg = "scan_id"

    def get_object(self, queryset=None):
        scan = super().get_object(queryset)
        scan_access(self.request.user, scan)
        return scan

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["dependencies"] = self.object.dependencies.select_related("scan")[:200]
        context["vulnerabilities"] = list(self.object.vulnerabilities.order_by("-cvss_score")[:200])
        context["recommendations"] = self.object.recommendations.select_related("vulnerability")[:100]
        context["license_records"] = self.object.license_records.all()[:200]
        context["source_status"] = self.object.sources
        return context
