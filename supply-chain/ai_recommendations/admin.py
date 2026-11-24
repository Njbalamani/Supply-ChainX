from django.contrib import admin

from .models import Recommendation


@admin.register(Recommendation)
class RecommendationAdmin(admin.ModelAdmin):
    list_display = ("title", "priority", "type", "source", "scan")
    list_filter = ("priority", "type", "source")
    search_fields = ("title", "explanation")
