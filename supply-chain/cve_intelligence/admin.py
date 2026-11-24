from django.contrib import admin

from .models import CVERecord, IntelSourceStatus


@admin.register(CVERecord)
class CVERecordAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "severity", "cvss_score", "source", "last_modified")
    search_fields = ("cve_id",)
    list_filter = ("severity", "source")


@admin.register(IntelSourceStatus)
class IntelSourceStatusAdmin(admin.ModelAdmin):
    list_display = ("name", "status", "last_attempt", "last_success", "request_count")
