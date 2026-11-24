from django.contrib import admin

from .models import SBOM


@admin.register(SBOM)
class SBOMAdmin(admin.ModelAdmin):
    list_display = ("serial_number", "scan", "spec_version", "sha256", "generated_at")
    search_fields = ("serial_number", "sha256")
