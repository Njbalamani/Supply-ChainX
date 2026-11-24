from django.contrib import admin

from .models import Project, ProjectArchive, Scan


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "ecosystem", "created_by", "created_at")
    list_filter = ("ecosystem",)
    search_fields = ("name", "slug", "repository_url")


@admin.register(ProjectArchive)
class ProjectArchiveAdmin(admin.ModelAdmin):
    list_display = ("original_filename", "project", "sha256", "size_bytes", "uploaded_at")
    search_fields = ("original_filename", "sha256")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "project", "status", "risk_score", "health_score", "created_at")
    list_filter = ("status",)
    date_hierarchy = "created_at"
