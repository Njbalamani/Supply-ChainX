from django.contrib import admin

from .models import LicenseRecord, LicenseReport


@admin.register(LicenseRecord)
class LicenseRecordAdmin(admin.ModelAdmin):
    list_display = ("package_name", "version", "spdx_id", "category", "compatible", "requires_review")
    list_filter = ("category", "compatible", "requires_review")
    search_fields = ("package_name", "license_id", "spdx_id")


@admin.register(LicenseReport)
class LicenseReportAdmin(admin.ModelAdmin):
    list_display = ("scan", "generated_at")
