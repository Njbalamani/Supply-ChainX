from django.urls import path

from . import views

app_name = "scans"

urlpatterns = [
    path("<int:scan_id>/", views.ScanDetailView.as_view(), name="detail"),
    path("<int:scan_id>/status/", views.ScanStatusView.as_view(), name="status"),
]
