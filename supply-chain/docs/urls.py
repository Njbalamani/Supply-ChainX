from django.urls import path

from . import views

app_name = "docs"

urlpatterns = [
    path("", views.DocsHomeView.as_view(), name="index"),
    path("architecture/", views.ArchitectureView.as_view(), name="architecture"),
    path("er-diagram/", views.ERDiagramView.as_view(), name="er_diagram"),
    path("api/", views.APIDocsView.as_view(), name="api"),
]
