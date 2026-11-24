from __future__ import annotations

import io
import os
import zipfile
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from accounts.models import User
from config.constants import OrgRole
from organizations.models import Organization, OrganizationMember
from projects.models import Project, Scan


class WebAndAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="owner", password="StrongPass123!", role="ADMIN")
        self.other = User.objects.create_user(username="outsider", password="StrongPass123!")
        self.org = Organization.objects.create(name="View Org", owner=self.user)
        OrganizationMember.objects.create(organization=self.org, user=self.user, role=OrgRole.OWNER)
        self.project = Project.objects.create(organization=self.org, name="web-app", created_by=self.user)
        self.scan = Scan.objects.create(project=self.project, triggered_by=self.user, status="COMPLETED")

    def test_public_and_authenticated_pages_render(self):
        self.assertEqual(self.client.get("/accounts/login/").status_code, 200)
        self.client.force_login(self.user)
        for path in ["/dashboard/", "/projects/", "/projects/%s/" % self.project.pk,
                     "/scans/%s/" % self.scan.pk, "/docs/", "/docs/architecture/",
                     "/docs/er-diagram/", "/docs/api/", "/organizations/"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_api_is_organization_scoped(self):
        self.client.force_login(self.user)
        response = self.client.get("/api/projects/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["name"] for item in response.json()["results"]], ["web-app"])

        self.client.logout()
        self.client.force_login(self.other)
        response = self.client.get("/api/projects/")
        self.assertEqual(response.json()["results"], [])

    def test_api_summary_and_schema(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/api/dashboard/summary/").status_code, 200)
        self.assertEqual(self.client.get("/api/schema/").status_code, 200)

    def test_upload_creates_scan_without_executing_code(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("requirements.txt", "requests==2.31.0\n")
            archive.writestr("payload.py", "import os; os.system('echo NEVER')\n")
        upload = SimpleUploadedFile("source.zip", buffer.getvalue(), content_type="application/zip")
        self.client.force_login(self.user)
        with patch("projects.views.dispatch_scan", return_value={"mode": "test"}) as dispatch:
            response = self.client.post("/projects/%s/upload/" % self.project.pk, {"archive": upload})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.project.scans.count(), 2)
        dispatch.assert_called_once()

    def test_outside_user_cannot_view_project(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.get("/projects/%s/" % self.project.pk).status_code, 403)


class LiveOSVIntegrationTests(TestCase):
    def test_live_osv_query_returns_structured_data(self):
        if os.environ.get("RUN_LIVE_OSV_TEST") != "1":
            self.skipTest("Set RUN_LIVE_OSV_TEST=1 to query the live OSV API.")
        from cve_intelligence.clients import osv_query_batch

        results = osv_query_batch([{"name": "requests", "version": "2.31.0", "ecosystem": "PYTHON"}])
        self.assertEqual(len(results), 1)
        self.assertIn("vulns", results[0])
