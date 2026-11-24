from django.contrib import admin

from .models import DependencyEdge, GraphMetric, RiskSignal


@admin.register(DependencyEdge)
class DependencyEdgeAdmin(admin.ModelAdmin):
    list_display = ("scan", "source", "target", "edge_type")
    search_fields = ("source", "target")


@admin.register(GraphMetric)
class GraphMetricAdmin(admin.ModelAdmin):
    list_display = ("scan", "node_count", "edge_count", "vulnerable_node_count", "risk_score")


@admin.register(RiskSignal)
class RiskSignalAdmin(admin.ModelAdmin):
    list_display = ("signal_type", "severity", "package_name_display", "scan")
    list_filter = ("signal_type", "severity")

    def package_name_display(self, obj):
        return obj.dependency.name if obj.dependency else "-"
