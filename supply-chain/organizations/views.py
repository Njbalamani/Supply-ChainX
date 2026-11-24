from __future__ import annotations

from django import forms
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView

from config.constants import OrgRole
from .models import Organization, OrganizationMember


class OrganizationCreateForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ("name", "description")


class OrganizationListView(LoginRequiredMixin, ListView):
    model = Organization
    template_name = "organizations/list.html"
    context_object_name = "organizations"

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Organization.objects.all()
        return Organization.objects.filter(memberships__user=self.request.user).distinct()


class OrganizationDetailView(LoginRequiredMixin, DetailView):
    model = Organization
    template_name = "organizations/detail.html"
    context_object_name = "organization"

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Organization.objects.all()
        return Organization.objects.filter(memberships__user=self.request.user).distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["members"] = self.object.memberships.select_related("user")
        context["projects"] = self.object.projects.all()
        context["can_edit"] = self.object.can_edit(self.request.user)
        context["roles"] = OrgRole.choices
        return context


class OrganizationCreateView(LoginRequiredMixin, CreateView):
    form_class = OrganizationCreateForm
    template_name = "organizations/create.html"
    success_url = reverse_lazy("organizations:list")

    def form_valid(self, form):
        form.instance.owner = self.request.user
        response = super().form_valid(form)
        OrganizationMember.objects.create(
            organization=self.object, user=self.request.user, role=OrgRole.OWNER
        )
        messages.success(self.request, "Organization created.")
        return response
