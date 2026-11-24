from django.contrib import admin

from .models import ParsedDependency


@admin.register(ParsedDependency)
class ParsedDependencyAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "ecosystem", "scan", "is_direct", "source_file")
    list_filter = ("ecosystem", "is_direct")
    search_fields = ("name", "version")
