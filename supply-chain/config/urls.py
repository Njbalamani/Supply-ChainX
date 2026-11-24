"""Root URL configuration for SupplyChainX."""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from dashboard.views import home

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("config.api_urls")),
    path("accounts/", include("accounts.urls", namespace="accounts")),
    path("organizations/", include("organizations.urls", namespace="organizations")),
    path("projects/", include("projects.urls", namespace="projects")),
    path("scans/", include("projects.scan_urls", namespace="scans")),
    path("dashboard/", include("dashboard.urls", namespace="dashboard")),
    path("reports/", include("reports.urls", namespace="reports")),
    path("docs/", include("docs.urls", namespace="docs")),
    path("", home, name="landing"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
