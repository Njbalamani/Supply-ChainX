from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    path("", views.OrganizationListView.as_view(), name="list"),
    path("new/", views.OrganizationCreateView.as_view(), name="create"),
    path("<int:pk>/", views.OrganizationDetailView.as_view(), name="detail"),
]
