from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.test import TestCase, override_settings

from accounts.models import User

from config.constants import Ecosystem, OrgRole, ScanStatus
from organizations.models import Organization, OrganizationMember
from projects.models import Project, ProjectArchive, Scan
from reports.services import create_report, pdf_bytes, vulnerability_csv_bytes
from sbom_generator.service import build_cyclonedx_document, generate_sbom
from vulnerability_scanner.tasks import run_scan

FAKE_OSV_VULN = {
    "id": "GHSA-test-1234",
    "aliases": ["CVE-2024-0001"],
    "summary": "Fixture advisory for deterministic pipeline tests",
    "details": "Fixture advisory details used only in tests.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
        }
    ],
    "references": [{"url": "https://example.test/advisory"}],
    "published": "2024-01-01T00:00:00Z",
    "modified": "2024-01-02T00:00:00Z",
    "database_specific": {"severity": "HIGH"},
}


TEST_MEDIA_ROOT = tempfile.mkdtemp(prefix="scx-tests-")


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT)
class ScanPipelineTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="analyst", password="StrongPass123!", role="ANALYST")
        self.org = Organization.objects.create(name="Acme Security", owner=self.user)
        OrganizationMember.objects.create(organization=self.org, user=self.user, role=OrgRole.OWNER)
        self.project = Project.objects.create(
            organization=self.org,
            name="payments-api",
            ecosystem=Ecosystem.PYTHON,
            created_by=self.user,
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("requirements.txt", "requests==2.31.0\nclick==8.1.7\n")
        self.archive = ProjectArchive(
            project=self.project,
            original_filename="source.zip",
            size_bytes=len(buffer.getvalue()),
            sha256="0" * 64,
            uploaded_by=self.user,
        )
        self.archive.file.save("test-source.zip", ContentFile(buffer.getvalue()), save=True)
        self.scan = Scan.objects.create(project=self.project, archive=self.archive, triggered_by=self.user)

    def test_full_scan_pipeline_with_mocked_osv(self):
        with patch("vulnerability_scanner.services.osv_query_batch") as batch, \
             patch("vulnerability_scanner.services.osv_fetch_vuln") as detail, \
             patch("vulnerability_scanner.services.nvd_fetch_cve", return_value=None):
            batch.side_effect = lambda deps: [
                {"vulns": [FAKE_OSV_VULN]} if d.name == "requests" else {} for d in deps
            ]
            detail.return_value = FAKE_OSV_VULN
            result = run_scan(self.scan.pk)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, ScanStatus.COMPLETED, self.scan.error_message)
        self.assertEqual(self.scan.dependencies.count(), 2)
        self.assertEqual(self.scan.vulnerabilities.count(), 1)
        vuln = self.scan.vulnerabilities.first()
        self.assertEqual(vuln.cve_id, "CVE-2024-0001")
        self.assertEqual(vuln.fixed_versions, ["2.32.0"])
        self.assertIn("OSV", vuln.sources)
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.cvss_score, 9.8)
        self.assertTrue(result["sbom_serial"].startswith("urn:uuid:"))

        sbom = self.scan.sbom
        self.assertEqual(sbom.document["bomFormat"], "CycloneDX")
        self.assertEqual(sbom.document["specVersion"], "1.5")
        purls = {c["purl"] for c in sbom.document["components"]}
        self.assertIn("pkg:pypi/requests@2.31.0", purls)
        self.assertEqual(sbom.document["dependencies"][0]["ref"], f"supplychainx:project:{self.project.pk}")

        self.assertEqual(self.scan.graph_metrics.node_count, 2)
        self.assertEqual(self.scan.graph_metrics.vulnerable_node_count, 1)
        self.assertTrue(self.scan.recommendations.filter(type="UPGRADE").exists())
        self.assertEqual(self.scan.license_records.count(), 2)

        pdf = pdf_bytes(self.scan)
        self.assertTrue(pdf.startswith(b"%PDF"))
        csv_data = vulnerability_csv_bytes(self.scan).decode("utf-8-sig")
        self.assertIn("CVE-2024-0001", csv_data)
        report = create_report(self.scan, "PDF", user=self.user)
        self.assertTrue(report.file.name.endswith(".pdf"))


class SBOMBuilderTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="dev", password="StrongPass123!")
        self.org = Organization.objects.create(name="SBOM Org", owner=self.user)
        self.project = Project.objects.create(organization=self.org, name="demo", created_by=self.user)
        self.scan = Scan.objects.create(project=self.project, triggered_by=self.user)

    def test_generate_sbom_is_idempotent_and_hashes_document(self):
        from dependency_parser.models import ParsedDependency

        ParsedDependency.objects.create(
            scan=self.scan,
            name="express",
            version="4.18.2",
            ecosystem=Ecosystem.NODE,
            source_file="package.json",
        )
        first = generate_sbom(self.scan)
        second = generate_sbom(self.scan)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.serial_number, second.serial_number)
        document = build_cyclonedx_document(self.scan)
        self.assertEqual(document["components"][0]["purl"], "pkg:npm/express@4.18.2")
        self.assertEqual(len(first.sha256), 64)
