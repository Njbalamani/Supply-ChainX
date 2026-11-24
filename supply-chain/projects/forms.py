from __future__ import annotations

from django import forms

from .models import Project


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ("name", "ecosystem", "description", "repository_url")
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
        }


class SourceArchiveForm(forms.Form):
    archive = forms.FileField(
        label="Source code ZIP",
        help_text="Archives are statically analysed only; contained code is never executed.",
    )

    def clean_archive(self):
        uploaded = self.cleaned_data["archive"]
        if not uploaded.name.lower().endswith(".zip"):
            raise forms.ValidationError("Only .zip archives are accepted.")
        if uploaded.size > 100 * 1024 * 1024:
            raise forms.ValidationError("Archive exceeds the 100 MB limit.")
        return uploaded
